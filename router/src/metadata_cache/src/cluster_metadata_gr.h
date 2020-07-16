/*
  Copyright (c) 2019, 2021, Oracle and/or its affiliates.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2.0,
  as published by the Free Software Foundation.

  This program is also distributed with certain software (including
  but not limited to OpenSSL) that is licensed under separate terms,
  as designated in a particular file or component or in included license
  documentation.  The authors of MySQL hereby grant you an additional
  permission to link the program and your derivative works with the
  separately licensed software that they have included with MySQL.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef METADATA_CACHE_CLUSTER_METADATA_GR_INCLUDED
#define METADATA_CACHE_CLUSTER_METADATA_GR_INCLUDED

#include "cluster_metadata.h"
#include "gr_notifications_listener.h"

struct GroupReplicationMember;
class GRMetadataBackend;

class METADATA_API GRClusterMetadata : public ClusterMetadata {
 public:
  /** @brief Constructor
   *
   * @param user The user name used to authenticate to the metadata server.
   * @param password The password used to authenticate to the metadata server.
   * @param connect_timeout The time after which trying to connect to the
   *                        metadata server should timeout (in seconds).
   * @param read_timeout The time after which read from metadata server should
   *                     timeout (in seconds).
   * @param connection_attempts The number of times a connection to metadata
   *                            must be attempted, when a connection attempt
   *                            fails.  NOTE: not used so far
   * @param ssl_options SSL related options to use for MySQL connections
   * @param use_cluster_notifications Flag indicating if the metadata cache
   * should use cluster notifications as an additional trigger for metadata
   * refresh
   */
  GRClusterMetadata(const std::string &user, const std::string &password,
                    int connect_timeout, int read_timeout,
                    int connection_attempts,
                    const mysqlrouter::SSLOptions &ssl_options,
                    const bool use_cluster_notifications = false);

  explicit GRClusterMetadata(const GRClusterMetadata &) = delete;
  GRClusterMetadata &operator=(const GRClusterMetadata &) = delete;

  /** @brief Destructor
   *
   * Disconnect and release the connection to the metadata node.
   */
  ~GRClusterMetadata() override;

  /** @brief Returns cluster topology defined in the metadata server
   *
   * @param cluster_name                the name of the cluster to query
   * @param cluster_type_specific_id    (GR ID for GR cluster, cluster_id for AR
   * cluster)
   * @return cluster topology object
   * @throws metadata_cache::metadata_error, MetadataUpgradeInProgressException
   */
  metadata_cache::ManagedCluster fetch_instances(
      const std::string &cluster_name,
      const std::string &cluster_type_specific_id) override;

  /** @brief Returns cluster topology defined in the metadata server
   *
   * Only to satisfy the API, not used for the GR Cluster
   *
   * @throws logic_error
   */
  metadata_cache::ManagedCluster fetch_instances(
      const std::vector<metadata_cache::ManagedInstance> & /*instances*/,
      const std::string & /*cluster_type_specific_id*/,
      std::size_t & /*instance_id*/) override {
    throw std::logic_error("Call to unexpected fetch_instances overload");
  }

  /** @brief Initializes the notifications listener thread (if a given cluster
   * type supports it)
   *
   * @param instances vector of the current cluster nodes
   * @param callback  callback function to get called when the GR notification
   *                  was received
   */
  void setup_notifications_listener(
      const std::vector<metadata_cache::ManagedInstance> &instances,
      const GRNotificationListener::NotificationClb &callback) override {
    if (gr_notifications_listener_)
      gr_notifications_listener_->setup(instances, callback);
  }

  /** @brief Deinitializes the notifications listener thread
   */
  void shutdown_notifications_listener() override {
    gr_notifications_listener_.reset();
  }

  /** @brief Returns cluster type this object is suppsed to handle
   */
  mysqlrouter::ClusterType get_cluster_type() override;

  /** @brief Get authentication data of the rest users from the metadata.
   *
   * Authentication data is stored in the router_rest_accounts table. This
   * method fetches the following information: username, password hash,
   * privileges and name of the authentication mechanism that should be used.
   *
   * @param cluster_name - name of the cluster
   *
   * @returns authentication data of the rest users stored in the metadata
   */
  auth_credentials_t fetch_auth_credentials(
      const std::string &cluster_name) override;

 protected:
  /** @brief Queries the metadata server for the list of instances that belong
   * to the desired cluster.
   */
  metadata_cache::ManagedCluster fetch_instances_from_metadata_server(
      const std::string &cluster_name,
      const std::string &cluster_type_specific_id);

  /** Query the GR performance_schema tables for live information about a
   * cluster.
   *
   * update_cluster_status() calls check_cluster_status() for some of its
   * processing. Together, they:
   * - check current topology (status) returned from a cluster node
   * - update 'instances' with this state
   * - get other metadata about the cluster
   *
   * The information is pulled from GR maintained performance_schema tables.
   */
  void update_cluster_status(const std::string &name,
                             metadata_cache::ManagedCluster &cluster);

  metadata_cache::ClusterStatus check_cluster_status(
      std::vector<metadata_cache::ManagedInstance> &instances,
      const std::map<std::string, GroupReplicationMember> &member_status,
      bool &metadata_gr_discrepancy) const noexcept;

  void reset_metadata_backend(const mysqlrouter::ClusterType type);
  std::unique_ptr<GRMetadataBackend> metadata_backend_;

 private:
  void update_backend(const mysqlrouter::MetadataSchemaVersion &version);

  std::unique_ptr<GRNotificationListener> gr_notifications_listener_;

#ifdef FRIEND_TEST
  FRIEND_TEST(MetadataTest, FetchInstancesFromMetadataServer);
  FRIEND_TEST(MetadataTest,
              UpdateClusterStatus_PrimaryMember_FailConnectOnNode2);
  FRIEND_TEST(MetadataTest,
              UpdateClusterStatus_PrimaryMember_FailConnectOnAllNodes);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_PrimaryMember_FailQueryOnNode1);
  FRIEND_TEST(MetadataTest,
              UpdateClusterStatus_PrimaryMember_FailQueryOnAllNodes);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_Status_FailQueryOnNode1);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_Status_FailQueryOnAllNodes);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_SimpleSunnyDayScenario);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_1Online1RecoveringNotInMetadata);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_3NodeSetup);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_VariableNodeSetup);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_VariousStatuses);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_PrimaryMember_EmptyOnNode1);
  FRIEND_TEST(MetadataTest, UpdateClusterStatus_PrimaryMember_EmptyOnAllNodes);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_Recovering);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_ErrorAndOther);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_Cornercase2of5Alive);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_Cornercase3of5Alive);
  FRIEND_TEST(MetadataTest, CheckClusterStatus_Cornercase1Common);
#endif
};

#endif  // METADATA_CACHE_CLUSTER_METADATA_AR_INCLUDED
