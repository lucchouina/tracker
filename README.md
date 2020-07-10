# tracker
scalable, multi-process and "always on" resource tracking for malloc and file descriptors
  
  Tracker is a heap allocation (malloc/free) and file-descriptor debugging and reporting framework.It is lightweight and can be used to track a set of applications simultaneously. It can be used by an individual developer that wants to validate their new code's memory usage and can also be used during the QA, system, and soak test cycles to monitor and report on memory hogs when abusive memory usage or upward trend in memory usage is detected.
  
  Tracker is a complementary technology to heavier memory debugging tools like Purify or Valgrind. These tools being heavy-handed on either the build side (special builds) or runtime (heavy impact on application performance). the tracker does not require any special compile or link time tools or options and has minimal impact on the performance of the application.
  
  Tracker uses the library interposition technics to perform its task
  
  Tracker is designed to provide a central console to monitor multiple processes at the same time   Tracker uses the concept of memory tagging which enables a true characterization of the application in all its phases (bring up, stabilization, steady-state …)No special compilation or linkage of the application and libraries is required. Tracker can be always present on the system and enabled by a reboot and tracking features turned on via the Tracker console commands.
