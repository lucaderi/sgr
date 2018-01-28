"""
This module export a simple abstract class
to help implementing a r2dlib database

"""

from abc import ABCMeta, abstractmethod


class DB(object):
    """
    Abstract class for a generic r2dlib database type

    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def meta(self):
        """
        Return the database metadata

        """

    @abstractmethod
    def fetch_data(self, start, stop, aggregation, resolution):
        """
        Return data stored in the database
        for a selected aggregation function

        Arguments:
        start: The initial time
        stop: The final time
        congregation: The desired function

        Optional Arguments:
        resolution: The desired resolution

        """

    @abstractmethod
    def get_sources(self):
        """
        Return datasources metadata

        """

    @abstractmethod
    def last(self):
        """
        Return the timestamp of the last stored values

        """

    @abstractmethod
    def insert(self, name, timestamp, value):
        """
        Store some values in the database

        Arguments:
        name: The name of the datasource
        timestamp: The time of the entry
        value: The values for the entry

        """

    @abstractmethod
    def get_aggregations(self, slot):
        """
        Return the aggregations that have to occur on the specified time slot

        Arguments:
        slot: The desired timeslot

        """

    @abstractmethod
    def get_lastreads(self, name, step):
        """
        Return the specified number of stored values

        Arguments:
        name: The name of the desired datasource
        step: The number of values that must return

        """

    @abstractmethod
    def store(self, aggregation, datasource, resolution,
              rows, timestamp, value):
        """
        Store an entry on the database

        Arguments:
        aggregation: The name of the aggregation function
        datasource: The name of the datasource
        resolution: The resolution of the aggregation function
        rows: The number of entry to keep
        timestamp: The time of the entry
        value: The value

        """

    @abstractmethod
    def partial(self, name):
        """
        Return the current partial result for the database if any

        """

    @abstractmethod
    def insert_partial(self, name, timestamp, newvalue):
        """
        Insert a new partial in the database

        Arguments:
        timestamp: The time of the entry
        newvalue: The value of the entry

        """
    def increment_last(self, timestamp):
        """
        Increment the timestamp of the last insertion according to timestamp

        """
