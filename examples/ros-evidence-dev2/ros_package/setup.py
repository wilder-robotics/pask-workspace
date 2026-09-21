# SPDX-License-Identifier: Apache-2.0
from setuptools import setup
setup(name="pask_ros2_local_demo", version="0.0.1",
      packages=["pask_ros2_local_demo"],
      data_files=[("share/ament_index/resource_index/packages", ["resource/pask_ros2_local_demo"]),
                  ("share/pask_ros2_local_demo", ["package.xml"])],
      install_requires=["setuptools"], zip_safe=True,
      maintainer="Local demo maintainer", maintainer_email="local-demo@example.invalid",
      description="Local simulated ROS evidence capture; runtime validation pending",
      license="Apache-2.0",
      entry_points={"console_scripts": ["capture_demo = pask_ros2_local_demo.node:main"]})
