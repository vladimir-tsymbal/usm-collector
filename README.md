Usmcollector is a standalone tool that collects implicit data transfers between Host and GPU device via i915 kernel module driver.
The tool is using eBPF technology for safely tracing i915 driver calls and providing data for reading in user space. The eBPF technology on x86_64 CPU architectures can run with Linux kernel 4.18 or higher.

The Usmcollector has these components:

- usmtool. This is a standalone tool that you can run from the command line or within Intel® VTune™ Profiler (as a custom collector
- A shared library that is available with a kernel module to collect memory events in the i915 kernel driver

In the general workflow, you run Usmcollector with sudo user privileges. To run the collector without sudo user privileges, you must first set the appropriate capabilities to the usmtool binary. Do one of the following:

- Run $ sudo setcap cap_bpf,cap_perfmon=+iep ./usmtool
- Run the set-usm-caps.sh script. This script is available with the Usmcollector.

The setcap utility might be not installed in the system. In ths case install the following library:
- "libcap" package for Red Hat Enterprise Linux/CentOS/Fedora distributions
- "libcap2-bin" package for Ubuntu/Debian distributions
- "libcap-progs" package for SLES/openSUSE distributions

It is required that debugfs file system is mounted and the mout point (the default is typically /sys/kernel/debug/) is accessible to a user.
For more information on mounting debugfs see the article: [DebugFS](https://docs.kernel.org/filesystems/debugfs.html)

Run Usmcollector as a Standalone Tool
```
    $ sudo set-usm-caps.sh -g <my_group>
    $ usmtool -print
    $ <run a workload in a separate console/window>
    $ Ctrl+C <this will send a signal to the collector process and gracefully stop collection>
    $ <data is printed out to the output pipe>
```

The output of the Usmcollector displays as four separate events. Each event has a timestamp prefix for a category:

- CPU Memory Faults
- GPU Memory Faults
- Memory Object Migration Events
- Memory Object Migration Latency
The migration of objects from the host to the GPU is denoted by **src smem, dst lmem**.
The migration of objects from the GPU to the host is denoted by **src lmem, dst smem**.

The Usmcollector can run together with VTune analysis, for example GPU analysis types. It can provide data transfer events and display them in the Platform tab on top of the processes timeline that initiated the transfers. While Intel® VTune™ Profiler can profile explicit USM data transfers, the Usmcollector profiles implicit data transfers. The collector is available with the 2024.0 (and newer) versions of VTune Profiler.

Run Usmcollector as a Custom Collector
```
    $ cd <VTUNE_INSTALL_DIR>/bin64
    $ sudo set-usm-caps.sh -g vtune
    $ sudo prepare-debugfs.sh -g vtune <use this script in case debugfs is not yet mouted>
    $ vtune -collect gpu-hotspots -custom-collector="python usmtool.py" -- <path_to_app>
```

usmtool.py is a script that implements custom collector control of VTune Profiler for the usmtool executable. In this example, the Usmcollector populates the results directory of the VTune GPU Media/Hotspots analysis with .csv files that contain data transfer events. The events are added by VTune Profiler on top of processes timeline in the Platform Tab.

Software requirements for Usmcollecor
- The eBPF technology on x86_64 CPU architectures can run with Linux kernel 4.18 or higher
- Setting CAP_BPF capability requires Linux Kernel 5.18 or later
- Linux Kernel build with the configuration option CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS
- It is recommended to increase memlock limits to ‘unlimited’

Hardware requirements for Usmcollecor
- Data collection supported on Intel® Data Center GPU Max Series


Get Help

To get help with Usmcollector or report feedback, open an Issue. 
