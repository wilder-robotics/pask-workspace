#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
source /opt/ros/jazzy/setup.bash
source /opt/demo_ws/install/setup.bash
mkdir -p /out
cp /opt/installed-dependencies.lock /out/installed-dependencies.lock
ros2 run pask_ros2_local_demo capture_demo collect --output /out/final-bundle > /out/collector.log 2>&1 &
collector=$!
sleep 1
ros2 run pask_ros2_local_demo capture_demo publish > /out/publisher.log 2>&1
wait "$collector"
