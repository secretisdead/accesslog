import sys
import unittest
import uuid
import time
from datetime import datetime, timezone

from ipaddress import ip_address
from sqlalchemy import create_engine

from testhelper import TestHelper, compare_base_attributes
from base64_url import base64_url_encode, base64_url_decode
from accesslog import AccessLog, LogEntry, parse_id

db_url = ''

class TestAccessLog(TestHelper):
	def setUp(self):
		if db_url:
			engine = create_engine(db_url)
		else:
			engine = create_engine('sqlite:///:memory:')

		self.access_log = AccessLog(
			engine,
			install=True,
			db_prefix=base64_url_encode(uuid.uuid4().bytes),
		)

	def tearDown(self):
		if db_url:
			self.access_log.uninstall()

	def assert_non_log_raises(self, f):
		# any non-log object should raise
		for invalid_log in [
				'string',
				1,
				['list'],
				{'dict': 'ionary'},
			]:
			with self.assertRaises(Exception):
				f(invalid_log)

	def test_parse_id(self):
		for invalid_input in [
				'contains non base64_url characters $%^~',
				['list'],
				{'dict': 'ionary'},
			]:
			with self.assertRaises(Exception):
				id, id_bytes = parse_id(invalid_input)
		expected_bytes = uuid.uuid4().bytes
		expected_string = base64_url_encode(expected_bytes)
		# from bytes
		id, id_bytes = parse_id(expected_bytes)
		self.assertEqual(id_bytes, expected_bytes)
		self.assertEqual(id, expected_string)
		# from string
		id, id_bytes = parse_id(expected_string)
		self.assertEqual(id, expected_string)
		self.assertEqual(id_bytes, expected_bytes)

	# class instantiation, create, get, and defaults
	def test_log_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			LogEntry,
			self.access_log.create_log,
			self.access_log.get_log,
			{
				'remote_origin': ip_address('127.0.0.1'),
				'scope': '',
				'subject_id': '',
				'object_id': '',
			},
		)

	#TODO assert properties that default to current time
	#TODO assert properties that default to uuid bytes

	# class instantiation and db object creation with properties
	# id properties
	def test_log_id_property(self):
		self.id_property(LogEntry, self.access_log.create_log, 'id')

	def test_log_subject_id_property(self):
		self.id_property(LogEntry, self.access_log.create_log, 'subject_id')

	def test_log_object_id_property(self):
		self.id_property(LogEntry, self.access_log.create_log, 'object_id')

	# time properties
	def test_log_creation_time_property(self):
		self.time_property(LogEntry, self.access_log.create_log, 'creation')

	# string properties

	def test_log_scope_property(self):
		self.string_property(
			LogEntry,
			self.access_log.create_log,
			'scope',
		)

	# delete
	def test_delete_log(self):
		self.delete(
			self.access_log.create_log,
			self.access_log.get_log,
			self.access_log.delete_log,
		)

	# id collision
	def test_logs_id_collision(self):
		self.id_collision(self.access_log.create_log)

	# unfiltered count
	def test_count_logs(self):
		self.count(
			self.access_log.create_log,
			self.access_log.count_logs,
			self.access_log.delete_log,
		)

	# unfiltered search
	def test_search_logs(self):
		self.search(
			self.access_log.create_log,
			self.access_log.search_logs,
			self.access_log.delete_log,
		)

	# sort order and pagination
	def test_search_logs_creation_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.access_log.create_log,
			'creation_time',
			self.access_log.search_logs,
		)

	def test_search_logs_scope_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.access_log.create_log,
			'scope',
			self.access_log.search_logs,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	# search by id
	def test_search_logs_by_id(self):
		self.search_by_id(
			self.access_log.create_log,
			'id',
			self.access_log.search_logs,
			'ids',
		)

	def test_search_logs_by_subject_id(self):
		self.search_by_id(
			self.access_log.create_log,
			'subject_id',
			self.access_log.search_logs,
			'subject_ids',
		)

	def test_search_logs_by_object_id(self):
		self.search_by_id(
			self.access_log.create_log,
			'object_id',
			self.access_log.search_logs,
			'object_ids',
		)

	# search by time
	def search_logs_by_creation_time(self):
		self.search_by_time_cutoff(
			self.access_log.create_log,
			'creation_time',
			self.access_log.search_logs,
			'created',
		)

	# search by string equal
	def test_search_logs_by_scope(self):
		self.search_by_string_equal(
			self.access_log.create_log,
			'scope',
			self.access_log.search_logs,
			'scopes',
		)

	# search by remote origin
	def test_search_logs_by_remote_origin(self):
		self.search_by_remote_origin(
			self.access_log.create_log,
			'remote_origin',
			self.access_log.search_logs,
			'remote_origins',
		)

	# scopes
	def test_get_unique_scopes(self):
		scope1 = 'test1'
		scope2 = 'test2'
		log1 = self.access_log.create_log(scope=scope1)
		log2 = self.access_log.create_log(scope=scope1)
		log3 = self.access_log.create_log(scope=scope2)
		unique_scopes = self.access_log.get_unique_scopes()
		self.assertEqual(2, len(unique_scopes))
		self.assertTrue(scope1 in unique_scopes)
		self.assertTrue(scope2 in unique_scopes)


	# logs
	def test_create_log_with_preset_remote_origin(self):
		preset_remote_origin = '1.1.1.1'
		self.access_log.remote_origin = '1.1.1.1'
		log = self.access_log.create_log()
		self.assertEqual(preset_remote_origin, log.remote_origin.exploded)

	def test_prune_logs_all(self):
		log1 = self.access_log.create_log(creation_time=1)
		log2 = self.access_log.create_log(creation_time=2)
		log3 = self.access_log.create_log(creation_time=3)

		self.assertIsNotNone(self.access_log.get_log(log1.id))
		self.assertIsNotNone(self.access_log.get_log(log2.id))
		self.assertIsNotNone(self.access_log.get_log(log3.id))

		self.access_log.prune_logs()

		self.assertIsNone(self.access_log.get_log(log1.id))
		self.assertIsNone(self.access_log.get_log(log2.id))
		self.assertIsNone(self.access_log.get_log(log3.id))

	def test_prune_logs_created_before(self):
		log1 = self.access_log.create_log(creation_time=1)
		log2 = self.access_log.create_log(creation_time=2)
		log3 = self.access_log.create_log(creation_time=3)

		self.assertIsNotNone(self.access_log.get_log(log1.id))
		self.assertIsNotNone(self.access_log.get_log(log2.id))
		self.assertIsNotNone(self.access_log.get_log(log3.id))

		self.access_log.prune_logs(created_before=3)

		self.assertIsNone(self.access_log.get_log(log1.id))
		self.assertIsNone(self.access_log.get_log(log2.id))
		self.assertIsNotNone(self.access_log.get_log(log3.id))

	def test_cooldown_remote_origin(self):
		remote_origin = '1.1.1.1'
		amount = 1
		period = 60
		scope = 'test'

		self.assertFalse(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				remote_origin=remote_origin,
			)
		)

		self.access_log.create_log(scope=scope, remote_origin=remote_origin)

		# explicit remote origin
		self.assertTrue(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				remote_origin=remote_origin,
			)
		)

		# preset remote origin is used if not specified
		self.access_log.remote_origin = remote_origin
		self.assertTrue(self.access_log.cooldown(scope, amount, period))

		# remote origin matches even logs with non-matching subject id
		self.assertTrue(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				remote_origin=remote_origin,
				subject_id=uuid.uuid4().bytes,
			)
		)

	def test_cooldown_subject_id(self):
		subject_id = uuid.uuid4().bytes
		amount = 1
		period = 60
		scope = 'test'

		self.assertFalse(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				subject_id=subject_id,
			)
		)

		self.access_log.create_log(scope=scope, subject_id=subject_id)

		self.assertTrue(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				subject_id=subject_id,
			)
		)

		# subject id matches even logs with non-matching remote_origin
		self.assertTrue(
			self.access_log.cooldown(
				scope,
				amount,
				period,
				remote_origin='1.1.1.1',
				subject_id=subject_id,
			)
		)

	def test_cooldown_range_and_amount_per_period(self):
		remote_origin = '1.1.1.1'
		self.access_log.remote_origin = remote_origin
		amount = 1
		period = 60
		scope = 'test'
		the_past = time.time() - period - 1

		# logs outside of the cooldown period aren't counted towards the amount
		self.access_log.create_log(scope=scope, creation_time=the_past)
		# multiple logs up to a cap can be set for a given period
		self.access_log.create_log(scope=scope)
		amount = 2
		self.assertFalse(self.access_log.cooldown(scope, amount, period))
		self.access_log.create_log(scope=scope)
		self.assertTrue(self.access_log.cooldown(scope, amount, period))

	# anonymization
	def test_anonymize_id(self):
		id = uuid.uuid4().bytes
		log_subject = self.access_log.create_log(subject_id=id)
		log_object = self.access_log.create_log(object_id=id)

		count_methods_filter_fields = [
			(self.access_log.count_logs, 'subject_ids'),
			(self.access_log.count_logs, 'object_ids'),
		]
		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(1, count(filter={filter_field: id}))

		new_id_bytes = self.access_log.anonymize_id(id)

		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(0, count(filter={filter_field: id}))

		# assert logs still exist, but with the new id as subject/object
		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(1, count(filter={filter_field: new_id_bytes}))

	#TODO passing in an id to use for anonymization is allowed, so test it
	def test_anonymize_id_with_new_id(self):
		pass

	def test_anonymize_log_origins(self):
		origin1 = '1.2.3.4'
		expected_anonymized_origin1 = '1.2.0.0'
		log1 = self.access_log.create_log(remote_origin=origin1)

		origin2 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
		expected_anonymized_origin2 = '2001:0db8:85a3:0000:0000:0000:0000:0000'
		log2 = self.access_log.create_log(remote_origin=origin2)

		logs = self.access_log.search_logs()
		self.access_log.anonymize_log_origins(logs)

		anonymized_log1 = self.access_log.get_log(log1.id)
		anonymized_log2 = self.access_log.get_log(log2.id)

		self.assertEqual(
			expected_anonymized_origin1,
			anonymized_log1.remote_origin.exploded,
		)
		self.assertEqual(
			expected_anonymized_origin2,
			anonymized_log2.remote_origin.exploded,
		)

if __name__ == '__main__':
	if '--db' in sys.argv:
		index = sys.argv.index('--db')
		if len(sys.argv) - 1 <= index:
			print('missing db url, usage:')
			print(' --db "dialect://user:password@server"')
			quit()
		db_url = sys.argv[index + 1]
		print('using specified db: "' + db_url + '"')
		del sys.argv[index:]
	else:
		print('using sqlite:///:memory:')
	print(
		'use --db [url] to test with specified db url'
			+ ' (e.g. sqlite:///accesslog_tests.db)'
	)
	unittest.main()
