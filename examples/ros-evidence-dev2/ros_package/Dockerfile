# SPDX-License-Identifier: Apache-2.0
# RECIPE ONLY: not built or run in the sandbox. Tag base is not an immutable lock.
# Build resolves OS/dependencies; record image digest + dpkg lock before claiming repeatability.
FROM ros:jazzy-ros-base
SHELL ["/bin/bash", "-c"]
ARG RCLPY_VERSION=7.1.12-1noble.20260902.053513
ARG RMW_VERSION=8.4.4-1noble.20260902.041916
ARG ROSBAG_PY_VERSION=0.26.11-1noble.20260903.090602
ARG ROSBAG_SQLITE_VERSION=0.26.11-1noble.20260903.070451
RUN test "$( . /etc/os-release; echo "$VERSION_ID" )" = 24.04 && \
    apt-get update && apt-get install -y --no-install-recommends \
      "ros-jazzy-rclpy=${RCLPY_VERSION}" \
      "ros-jazzy-rmw-fastrtps-cpp=${RMW_VERSION}" \
      "ros-jazzy-rosbag2-py=${ROSBAG_PY_VERSION}" \
      "ros-jazzy-rosbag2-storage-sqlite3=${ROSBAG_SQLITE_VERSION}" \
      ros-jazzy-geometry-msgs ros-jazzy-diagnostic-msgs python3-cryptography \
      python3-colcon-common-extensions && \
    dpkg-query -W > /opt/installed-dependencies.lock
# Ubuntu cryptography version may lack public_bytes_raw(): Python code uses explicit serialization below.
COPY bundle.py /opt/demo/bundle.py
COPY ros_package /opt/demo_ws/src/pask_ros2_local_demo
RUN source /opt/ros/jazzy/setup.bash && cd /opt/demo_ws && colcon build
ENV PYTHONPATH=/opt/demo
ENV RMW_IMPLEMENTATION=rmw_fastrtps_cpp
ENV ROS_DOMAIN_ID=173
ENV ROS_AUTOMATIC_DISCOVERY_RANGE=LOCALHOST
ENV ROS_STATIC_PEERS=""
ENV PASK_ISOLATED_DEMO=container-network-none
ENV ROS_LOG_DIR=/tmp/ros-log
COPY ros_package/run-isolated.sh /opt/run-isolated.sh
ENTRYPOINT ["/bin/bash", "/opt/run-isolated.sh"]
