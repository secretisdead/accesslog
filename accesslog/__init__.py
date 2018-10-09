import uuid
import time
import re
from ipaddress import ip_address
from enum import Enum
from datetime import datetime, timezone

from sqlalchemy import Table, Column, LargeBinary
from sqlalchemy import Integer, String, MetaData, distinct
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func, and_

from statement_helper import sort_statement, paginate_statement, id_filter
from statement_helper import time_cutoff_filter, string_equal_filter
from statement_helper import remote_origin_filter
from idcollection import IDCollection
from parse_id import parse_id, get_id_bytes, generate_or_parse_id

class LogEntry:
	def __init__(
			self,
			id=None,
			creation_time=None,
			scope='',
			remote_origin='127.0.0.1',
			subject_id='',
			object_id='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		if None == creation_time:
			creation_time = time.time()
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.scope = str(scope)

		self.remote_origin = ip_address(remote_origin)

		self.subject_id, self.subject_id_bytes = parse_id(subject_id)
		self.subject = None

		self.object_id, self.object_id_bytes = parse_id(object_id)
		self.object = None

class AccessLog:
	def __init__(self, engine, db_prefix='', install=False, remote_origin=None):
		self.engine = engine
		self.engine_session = sessionmaker(bind=self.engine)()

		self.db_prefix = db_prefix

		self.remote_origin = remote_origin

		self.scope_length = 16

		metadata = MetaData()

		default_bytes = 0b0 * 16

		# logs tables
		self.logs = Table(
			self.db_prefix + 'access_logs',
			metadata,
			Column(
				'id',
				LargeBinary(16),
				primary_key=True,
				default=default_bytes
			),
			Column('creation_time', Integer, default=0),
			Column('scope', String(self.scope_length)),
			Column(
				'remote_origin',
				LargeBinary(16),
				default=ip_address(default_bytes)
			),
			Column(
				'subject_id',
				LargeBinary(16),
				default=default_bytes
			),
			Column(
				'object_id',
				LargeBinary(16),
				default=default_bytes
			),
		)

		self.connection = self.engine.connect()

		if install:
			table_exists = self.engine.dialect.has_table(
				self.engine,
				self.db_prefix + 'access_logs'
			)
			if not table_exists:
				metadata.create_all(self.engine)

	def uninstall(self):
		for table in [
				self.logs,
			]:
			table.drop(self.engine)

	# retrieve logs
	def get_log(self, id):
		logs = self.search_logs(filter={'ids': id})
		return logs.get(id)

	def prepare_logs_search_statement(self, filter):
		conditions = []
		conditions += id_filter(filter, 'ids', self.logs.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.logs.c.creation_time,
		)
		conditions += string_equal_filter(
			filter,
			'scopes',
			self.logs.c.scope,
		)
		conditions += remote_origin_filter(
			filter,
			'remote_origins',
			self.logs.c.remote_origin,
		)
		conditions += id_filter(
			filter,
			'subject_ids',
			self.logs.c.subject_id,
		)
		conditions += id_filter(
			filter,
			'object_ids',
			self.logs.c.object_id,
		)

		statement = self.logs.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_logs(self, filter={}):
		statement = self.prepare_logs_search_statement(filter)
		statement = statement.with_only_columns(
			[func.count(self.logs.c.id)]
		)
		return self.connection.execute(statement).fetchone()[0]

	def search_logs(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		statement = self.prepare_logs_search_statement(filter)

		statement = sort_statement(
			statement,
			self.logs,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		logs = IDCollection()
		for row in result:
			log = LogEntry(
				id=row[self.logs.c.id],
				creation_time=row[self.logs.c.creation_time],
				scope=row[self.logs.c.scope],
				remote_origin=row[self.logs.c.remote_origin],
				subject_id=row[self.logs.c.subject_id],
				object_id=row[self.logs.c.object_id],
			)

			logs.add(log)
		return logs

	# manipulate logs
	def create_log(self, **kwargs):
		if 'remote_origin' not in kwargs and self.remote_origin:
			kwargs['remote_origin'] = self.remote_origin
		log = LogEntry(**kwargs)
		# preflight check for existing id
		if self.count_logs(filter={'ids': log.id_bytes}):
			raise ValueError('Log ID collision')
		self.connection.execute(
			self.logs.insert(),
			id=log.id_bytes,
			creation_time=int(log.creation_time),
			scope=str(log.scope),
			remote_origin=log.remote_origin.packed,
			subject_id=log.subject_id_bytes,
			object_id=log.object_id_bytes,
		)
		return log

	def prune_logs(self, created_before=None):
		conditions = [0 != self.logs.c.creation_time]
		if created_before:
			conditions.append(int(created_before) > self.logs.c.creation_time)
		self.connection.execute(
			self.logs.delete().where(and_(*conditions))
		)

	def delete_log(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.logs.delete().where(self.logs.c.id == id)
		)

	# cooldown
	def cooldown(
			self,
			scope,
			amount,
			period,
			remote_origin=None,
			subject_id=None,
		):
		start_time = time.time() - period
		if not remote_origin and self.remote_origin:
			remote_origin = self.remote_origin
		if remote_origin:
			filter = {
				'scopes': scope,
				'created_after': start_time,
				'remote_origins': remote_origin,
			}
			if amount <= self.count_logs(filter=filter):
				return True
		if subject_id:
			filter = {
				'scopes': scope,
				'created_after': start_time,
				'subject_id': subject_id,
			}
			if amount <= self.count_logs(filter=filter):
				return True
		return False

	# unique scopes
	def get_unique_scopes(self):
		statement = self.logs.select().with_only_columns(
			[self.logs.c.scope]
		).group_by(self.logs.c.scope)
		result = self.engine.execute(statement).fetchall()
		unique_scopes = []
		for row in result:
			unique_scopes.append(row[self.logs.c.scope])
		return unique_scopes

	# anonymization
	def anonymize_id(self, id, new_id=None):
		id = get_id_bytes(id)

		if not new_id:
			new_id = uuid.uuid4().bytes

		self.connection.execute(
			self.logs.update().values(subject_id=new_id).where(
				self.logs.c.subject_id == id,
			)
		)
		self.connection.execute(
			self.logs.update().values(object_id=new_id).where(
				self.logs.c.object_id == id,
			)
		)

		return new_id

	def anonymize_log_origins(self, logs):
		for log in logs.values():
			if 4 == log.remote_origin.version:
				# clear last 16 bits
				anonymized_origin = ip_address(
					int.from_bytes(log.remote_origin.packed, 'big')
					&~ 0xffff
				)
			elif 6 == log.remote_origin.version:
				# clear last 80 bits
				anonymized_origin = ip_address(
					int.from_bytes(log.remote_origin.packed, 'big')
					&~ 0xffffffffffffffffffff
				)
			else:
				raise ValueError('Encountered unknown IP version')
			self.connection.execute(
				self.logs.update().values(
					remote_origin=anonymized_origin.packed
				).where(
					self.logs.c.id == log.id_bytes
				)
			)
