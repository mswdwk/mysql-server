/* Copyright (c) 2014 Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */




#ifndef RPL_MSR_H
#define RPL_MSR_H

#ifdef HAVE_REPLICATION

#include<map>
#include<string>
#include "rpl_mi.h"


/**
   Maps a channel name to it's Master_info.
*/


typedef std::map<std::string, Master_info*> mi_map;

/**
  Class to store all the Master_info objects of a slave
  to access them in the replication code base or performance
  schema replication tables.

  In a Multisourced replication setup, a slave connects
  to several masters (also called as sources). This class
  stores the Master_infos where each Master_info belongs
  to a slave.

  The important objects for a slave are the following:
  i) Master_info and Relay_log_info (slave_parallel_workers == 0)
  ii) Master_info, Relay_log_info and Slave_worker(slave_parallel_workers >0 )

  Master_info is always assosiated with a Relay_log_info per channel.
  So, it is enough to store Master_infos and call the corresponding
  Relay_log_info by mi->rli;

  This class is not yet thread safe. Any part of replication code that
  calls this class member function should always Lock the mutex LOCK_msr_map.

  Only a single global object for a server instance should be created.

  The two important data structures in this class are
  i) c++ std map to store the Master_info pointers with channel name as a key.
    @TODO: convert to boost after it's introduction.
  ii) An array of Master_info pointers to access from performance schema
     tables. This array is specifically is implemented in a way to make
      a) pfs indices simple i.e a simple integer counter
      b) To avoid recalibration of data structure if master info is deleted.
         * Consider the following high level implementation of a pfs table
            to make a row.
          <pseudo_code>
          highlevel_pfs_funciton()
          {
           while(replication_table_xxxx.rnd_next())
           {
             do stuff;
             }
          }
         </pseudo_code>
         However, we lock LOCK_msr_map for every rnd_next(); There is a gap
         where an addition/deletion of a channel would rearrange the map
         making the integer indices of the pfs table point to a wrong value.
         Either missing a row or duplicating a row.

         We solve this problem, by using an array exclusively to use in
         replciation pfs tables, by marking a master_info defeated as 0
         (i.e NULL). A new master info is added to this array at the
         first NULL always.

  @todo: Make this class a singleton, so that only one object exists for an
         instance.

  @optional_todo: since every select * in replication pfs table depends on
         LOCK_msr_map, think of either splitting the lock into rw lock
         OR making a copy of all slave_info_objects for info display.
*/
class Multisource_info
{

private:
 /* Maximum number of channels per slave */
  static const unsigned int MAX_CHANNELS= 256;

 /* A Map that maps, a channel name to a Master_info */
  mi_map channel_to_mi;

  /* Array for  performance schema related tables */
  Master_info *pfs_mi[MAX_CHANNELS];

  /* Number of master_infos at the moment*/
  uint current_mi_count;

  /**
    Default_channel for this instance, currently is predefined
    and cannot be modified.
  */
  static const char* default_channel;

  /**
     Get the index of the master info correposponding to channel name
     from the pfs_mi array.
  */
  int get_index_from_pfs_mi(const char* channel_name);

public:

  /* Constructor for this class.*/

  Multisource_info()
  {
    current_mi_count= 0;
    for (uint i= 0; i < MAX_CHANNELS; i++)
      pfs_mi[i]= 0;
  }

  /**
    Adds the Master_info object to both channel_to_mi and multisource_mi

    @param[in]   channel     channel name
    @param[mi]   mi          pointer to master info corresponding
                             to this channel

    @return
      @retval      FALSE       succesfully added to the map
      @retval      TRUE        ok.
  */
  bool add_mi(const char* channel_name, Master_info* mi);

  /**
    Find the master_info object corresponding to a channel explicitly
    from channel_to_mi;
    Return if it exists, otherwise return 0

    @param[in]  channel       channel name for the master info object.

    @retval                   pointer to the master info object if exists
                              in the map. Otherwise, NULL;
  */
  Master_info* get_mi(const char* channel_name);

  /**
    Remove the entry corresponding to the channel, from the channel_to_mi
    and sets index in the  multisource_mi to 0;
    And also delete the {mi, rli} pair corresponding to this channel

    @param[in]    channel_name     Name of the channel for a Master_info object
    @return
      @retval     false            succesfully deleted.
      @retval     true             not ok
  */
  bool delete_mi(const char* channel_name);

  /**
    Used only by replication performance schema indices to get the master_info
    at the position 'pos' from the multisource_mi array.

    @param[in]   pos   the index in the pfs_mi array
    @retval           pointer to the master info object at pos 'pos';
  */
  Master_info* get_mi_at_pos(uint pos);

  /**
     Return a channel name from the map having the same host and port.

    @param[in]         host         host of the new channel.
    @param[in]         port         port of the new channel.

    @return            channel_name  channel in the map with same host and port.
                                     If no such channel, exists, return 0
 */
  const char* get_channel_with_host_port(char* host, uint port);

  /**
    Get the default channel for this multisourced_slave;
  */
  inline const char* get_default_channel()
  {
    return default_channel;
  }

  /**
     Get the number of instances of Master_info in the map.
  */
  inline uint get_num_instances()
  {
    return channel_to_mi.size();
  }

  /**
    Get max channels allowed for this map.
  */
  inline uint get_max_channels()
  {
    return MAX_CHANNELS;
  }

  /**
    Returns true if the current number of channels in this slave
    is less than the MAX_CHANNLES
  */
  inline bool is_valid_channel_count()
  {
    return (current_mi_count < MAX_CHANNELS);
  }

  /**
     Forward iterators to initiate traversing of a map.

     @todo: Not to expose iterators. But instead to return
            only Master_infos or create generators when
            c++11 is introduced.
  */
  mi_map::iterator begin()
  {
    return channel_to_mi.begin();
  }

  mi_map::iterator end()
  {
    return channel_to_mi.end();
  }

};

/* Global object for multisourced slave. */
extern Multisource_info  msr_map;

#endif   /* HAVE_REPLICATION */
#endif  /*RPL_MSR_H*/
