# Modular Python Bitcoin Miner
# Copyright (C) 2012 Michael Sparmann (TheSeven)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Please consider donating to 1PLAPWDejJPJnY2ppYCgtw5ko8G5Q4hPzh if you
# want to support further development of the Modular Python Bitcoin Miner.



"""cpuminer.py

Simple reference implementation of a cpu-based miner

Not useful for actual mining, but will demonstrate that the system works and
is connected to the pool and contributing shares (however slowly)
"""

import time
import struct
import traceback
from threading import Condition, Thread
from binascii import hexlify, unhexlify
from core.baseworker import BaseWorker
from core.job import ValidationJob


# Worker main class, referenced from __init__.py
class DemoCPUWorker(BaseWorker):
    
    version = "cpuminer.cpuminer worker v0.1.9"
    default_name = "Demonstration cpu-based worker"
    settings = dict(BaseWorker.settings, **{
        "port": {"title": "Port", "type": "string", "position": 1000},
        "baudrate": {"title": "Baud rate", "type": "int", "position": 1100},
        "jobinterval": {"title": "Job interval", "type": "float", "position": 1200},
    })

    def __init__(self, core, state=None):
        # Let our superclass do some basic initialization and
        # state restoration if necessary
        super(DemoCPUWorker, self).__init__(core, state)

        # wakeup flag for main thread - also serves as a lock
        self.wakeup = Condition()

    def apply_settings(self):
        """Validate settings, applying default values where necessary
        
        This is called from __init__, and after every settings change
        """
        super(DemoCPUWorker, self).apply_settings()
        
        # supply defaults for any missing settings
        if not "port" in self.settings or not self.settings.port:
            self.settings.port = "/dev/ttyS0"
        if not "baudrate" in self.settings or not self.settings.baudrate:
            self.settings.baudrate = 115200
        if not "jobinterval" in self.settings or not self.settings.jobinterval:
            self.settings.jobinterval = 60
        
        # We can't change the port name or baud rate on the fly, so trigger a restart if they changed
        # self.port/self.baudrate are cached copys of self.settings.port/self.settings.baudrate
        if self.started and \
                (self.settings.port != self.port or \
                self.settings.baudrate != self.baudrate):
            self.async_restart()

    def _reset(self):
        """Resets the state
        Called from __init__ and from self.start()
        """
        super(DemoCPUWorker, self)._reset()
        
        # These need to be set here in order to make the equality check
        # in apply_settings() happy when it is run before starting the
        # module for the first time (when called from __init__)
        self.port = None
        self.baudrate = None
#        # Initialize custom statistics. This is not neccessary for this worker module,
#        # but might be interesting for other modules, so it is kept here for reference.
#        self.stats.field1 = 0
#        self.stats.field2 = 0
#        self.stats.field3 = 0

    def _start(self):
        """Starts the worker module
        Protected against multiple concurrent calls by a wrapper
        """
        super(DemoCPUWorker, self)._start()
        
        # Cache the port number and baud rate so we're not affected by
        # on-the-fly changes
        self.port = self.settings.port
        self.baudrate = self.settings.baudrate
        
        # Assume a default job interval to make the core start fetching
        # work for us. The actual hashrate will be measured (and this
        # adjusted to the correct value) later
        self.jobs_per_second = 1. / self.settings.jobinterval
        
        # This worker will only ever process one job at once. The work
        # fetcher needs this information to estimate how many jobs might
        # be required at once in the worst case (after a block was found)
        self.parallel_jobs = 1
        
        # Reset the shutdown flag for our threads
        self.shutdown = False
        
        # Start up the main thread which pushes work to the device
        self.mainthread = Thread(None, self.main, self.settings.name + "_main")
        self.mainthread.daemon = True
        self.mainthread.start()

    def _stop(self):
        """Shut down the worker module
        Also protected against multiple concurrent calls by a wrapper
        """
        super(DemoCPUWorker, self)._stop()
        
        # makes threads terminate ASAP
        self.shutdown = True
        
        # makes main thread wakeup to check the shutdown flag
        with self.wakeup:
            self.wakeup.notify()
        
        # The listener thread will hopefully die because the main thread
        # closes the serial port handle.
        # Listener thread dies before the main thread
        self.mainthread.join(10)

    def notify_canceled(self, job, graceful):
        """Interrupts processing on the given job (if the job
        belongs to this worker and is currently being worked on)
 
        Helps avoid producing stale shares after a new block.
        
        Note:
         Never attempt to fetch a new job in here, always do that
         asynchronously! This method needs to be very lightweight
         and fast. We don't care whether it's a graceful cancellation
         for this module because the work upload overhead is low
        """
        
        # Acquire the wakeup lock to make sure that nobody modifies
        # job/nextjob while we're looking at them
        with self.wakeup:
            # If the currently being processed, or currently being uploaded
            # job are affected, wake up the main thread so that it can request
            # and upload a new job immediately
            if self.job == job or self.nextjob == job:
                self.wakeup.notify()

                
#    # Report custom statistics. This is not neccessary for this worker module,
#    # but might be interesting for other modules, so it is kept here for reference.
#    def _get_statistics(self, stats, childstats):
#        # Let our superclass handle everything that isn't specific to this worker module
#        super(DemoCPUWorker, self)._get_statistics(stats, childstats)
#        stats.field1 = self.stats.field1
#        stats.field2 = self.stats.field2 + childstats.calculatefieldsum("field2")
#        stats.field3 = self.stats.field3 + childstats.calculatefieldavg("field3")

    def main(self):
        """Main thread entry point
        Responsible for fetching work and pushing it to the device
        Runs in a separate thread
        """
        # Counts exception frequency. Gets reset after ~5min of no exceptions
        tries = 0
        
        # If we're currently shutting down, just die. If not, loop forever,
        # to recover from possible errors caught by the huge try statement
        # inside this loop.
        while not self.shutdown:
            try:
                # help us know when to back off on repeated errors
                starttime = time.time()
                
                # Exception container: If an exception occurs in the listener thread, the listener thread
                # will store it here and terminate, and the main thread will rethrow it and then restart.
                self.error = None

                # Initialize megahashes per second to zero, will be measured later.
                self.stats.mhps = 0

                # Job that the device is currently working on (found nonces come from this one).
                # This variable is used by BaseWorker to figure out the current work source for statistics.
                self.job = None
                # Job that is currently being uploaded to the device but not yet being processed.
                self.nextjob = None

                # create a job handler and sync to it
                self.handle = CPUJobHandler()
                self.handle.sync()

                # We keep control of the wakeup lock at all times unless we're sleeping
                self.wakeup.acquire()
                
                # Set validation success flag to false
                self.checksuccess = False
                
                # Start device response listener thread
                self.listenerthread = \
                    Thread(None, self._listener, self.settings.name + "_listener")
                self.listenerthread.daemon = True
                self.listenerthread.start()

                # Send validation job to device
                job = ValidationJob(self.core, 
                                    unhexlify(b"00000001c3bf95208a646ee98a"+\
                                                "58cf97c3a0c4b7bf5de4c89ca"+\
                                                "04495000005200000000024d1"+\
                                                "fff8d5d73ae11140e4e48032c"+\
                                                "d88ee01d48c67147f9a09cd41"+\
                                                "fdec2e25824f5c038d1a0b350c5eb01f04"))
                self._sendjob(job)

                # Wait for validation job to be accepted by the device
                self.wakeup.wait(1)
                
                # If an exception occurred in the listener thread, rethrow it
                if self.error is not None:
                    raise self.error
                
                # Honor shutdown flag
                if self.shutdown:
                    break
                
                # If the job that was enqueued above has not been moved from nextjob to job by the
                # listener thread yet, something went wrong. Throw an exception to make everything restart.
                if self.nextjob is not None:
                    raise Exception("Timeout waiting for job ACK")

                # Wait for the validation job to complete. The wakeup flag will be set by the listener
                # thread when the validation job completes. 60 seconds should be sufficient for devices
                # down to about 1.3MH/s, for slower devices this timeout will need to be increased.
                self.wakeup.wait(60)
                
                # If an exception occurred in the listener thread, rethrow it
                if self.error is not None:
                    raise self.error
                
                # Honor shutdown flag
                if self.shutdown:
                    break
                
                # We woke up, but the validation job hasn't succeeded in the mean time.
                # This usually means that the wakeup timeout has expired.
                if not self.checksuccess:
                    raise Exception("Timeout waiting for validation job to finish")
                
                # self.stats.mhps has now been populated by the listener thread
                self.core.log(self, "Running at %f MH/s\n" % self.stats.mhps, 300, "B")
                
                # Calculate the time that the device will need to process 2**32 nonces.
                # This is limited at 60 seconds in order to have some regular communication,
                # even with very slow devices (and e.g. detect if the device was unplugged).
                interval = min(60, 2**32 / 1000000. / self.stats.mhps)
                
                # Add some safety margin and take user's interval setting (if present) into account.
                self.jobinterval = min(self.settings.jobinterval,
                                        max(0.5, interval * 0.8 - 1))
                self.core.log(self, "Job interval: %f seconds\n" % self.jobinterval, 400, "B")
                
                # Tell the MPBM core that our hash rate has changed
                # so that it can adjust its work buffer
                self.jobspersecond = 1. / self.jobinterval
                self.core.notify_speed_changed(self)

                # Main loop, continues until something goes wrong or we're shutting down.
                while not self.shutdown:

                    # Fetch a job, add 2 seconds safety margin to the
                    # requested minimum expiration time
                    # Blocks until one is available so we need to release the
                    # wakeup lock temporarily in order to avoid deadlocking
                    self.wakeup.release()
                    job = self.core.get_job(self, self.jobinterval + 2)
                    self.wakeup.acquire()
                    
                    # If a new block was found while we were fetching that job, just discard it and get a new one.
                    if job.canceled:
                        job.destroy()
                        continue

                    # If an exception occurred in the listener thread, rethrow it
                    if self.error is not None:
                        raise self.error

                    # Upload the job to the device
                    self._sendjob(job)
                    
                    # Wait for up to one second for the device to accept it
                    self.wakeup.wait(1)
                    
                    # Honor shutdown flag
                    if self.shutdown:
                        break
                    
                    # If an exception occurred in the listener thread, rethrow it
                    if self.error is not None:
                        raise self.error
                    
                    # If the job that was sent above has not been moved from
                    # nextjob to job by the listener thread yet, something
                    # went wrong
                    if self.nextjob is not None:
                        raise Exception("Timeout waiting for job ACK")
                    
                    # If the job was already caught by a long poll while we were uploading it,
                    # jump back to the beginning of the main loop in order to immediately fetch new work.
                    # Don't check for the canceled flag before the job was accepted by the device,
                    # otherwise we might get out of sync.
                    if self.job.canceled:
                        continue
                    
                    # Wait while the device is processing the job. If nonces are sent by the device, they
                    # will be processed by the listener thread. If the job gets canceled, we will be woken up.
                    self.wakeup.wait(self.jobinterval)
                    
                    # re-throw exceptions from the listener thread
                    if self.error is not None:
                        raise self.error

            except Exception as e:
                # ...complain about it!
                self.core.log(self, "%s\n" % traceback.format_exc(), 100, "rB")
                
                # Make sure that the listener thread realizes that something went wrong
                self.error = e
                
            finally:
                # We're not doing productive work any more, update stats and destroy current job
                self._jobend()
                self.stats.mhps = 0
                
                # Release the wake lock to allow the listener thread to move
                try:
                    self.wakeup.release()
                except:
                    pass
                
                # Close the serial port handle, otherwise we can't reopen it after restarting.
                # This should hopefully also make reads on that port from the listener thread fail,
                # so that the listener thread will realize that it's supposed to shut down.
                try:
                    self.handle.close()
                except:
                    pass
                
                # Wait for the listener thread to terminate.
                # If it doens't within 5 seconds, continue anyway. We can't do much about that.
                try:
                    self.listenerthread.join(5)
                except:
                    pass
                
                # Set MH/s to zero again, the listener thread might have overwritten that.
                self.stats.mhps = 0
                
                # If we aren't shutting down, figure out if there have been many errors recently,
                # and if yes, wait a bit longer until restarting the worker.
                if not self.shutdown:
                    tries += 1
                    if time.time() - starttime >= 300:
                        tries = 0
                    
                    with self.wakeup:
                        if tries > 5:
                            self.wakeup.wait(30)
                        else:
                            self.wakeup.wait(1)
                # Restart (handled by "while not self.shutdown:" loop above)

    def _listener(self):
        """Calculates hashes instead of passing a job off to a worker
        """
        # catch and forward exceptions to the main thread
        try:
            while True:
                if nextjob is None:
                    
            
                job_data = self.nextjob.midstate[::-1] + \
                            self.nextjob.data[75:63:-1]
                
                

    def _old_listener(self):
        """Device response listener thread
        """
        # Catch all exceptions and forward them to the main thread
        try:
            # Loop forever unless something goes wrong
            while True:
                # If the main thread has a problem, make sure we die before it restarts
                if self.error is not None:
                    break

                # Try to read a response from the device
                data = self.handle.read(1)
                
                # If no response was available, retry
                if len(data) == 0:
                    continue
                
                # Decode the response
                result = struct.unpack("B", data)[0]

                if result == 1:
                    # Got a job acknowledgement message.
                    # If we didn't expect one (no job waiting to be accepted in nextjob), throw an exception.
                    if self.nextjob == None:
                        raise Exception("Got spurious job ACK from mining device")
                    
                    # The job has been uploaded. Start counting time for the new job, and if there was a
                    # previous one, calculate for how long that one was running and destroy it.
                    now = time.time()
                    self._jobend(now)

                    # Acknowledge the job by moving it from nextjob to job and wake up
                    # the main thread that's waiting for the job acknowledgement.
                    with self.wakeup:
                        self.job = self.nextjob
                        self.job.starttime = now
                        self.nextjob = None
                        self.wakeup.notify()

                elif result == 2:
                    # We found a share! Download the nonce.
                    nonce = self.handle.read(4)[::-1]
                    
                    # If there is no job, this must be a leftover from somewhere, e.g. previous invocation
                    # or reiterating the keyspace because we couldn't provide new work fast enough.
                    # In both cases we can't make any use of that nonce, so just discard it.
                    if self.job is None:
                        continue
                    
                    # Stop time measurement
                    now = time.time()
                    
                    # Pass the nonce that we found to the work source, if there is one.
                    # Do this before calculating the hash rate as it is latency critical.
                    self.job.nonce_found(nonce)
                    
                    # If the nonce is too low this measurement may be inaccurate
                    nonceval = struct.unpack("<I", nonce)[0]
                    if nonceval >= 0x02000000:
                        # Calculate actual on-device processing time (not including transfer times) of the job.
                        delta = (now - self.job.starttime) - 40. / self.baudrate
                        
                        # Calculate the hash rate based on the processing time and number of neccessary MHashes.
                        # This assumes that the device processes all nonces (starting at zero) sequentially.
                        self.stats.mhps = nonceval / delta / 1000000.
                        self.core.event(350, self, "speed", self.stats.mhps * 1000, "%f MH/s" % self.stats.mhps, worker=self)
                        
                    # This needs self.mhps to be set.
                    if isinstance(self.job, ValidationJob):
                        # This is a validation job. Validate that the nonce is correct, and complain if not.
                        if self.job.nonce != nonce:
                            raise Exception("Mining device is not working correctly (returned %s instead of %s)" % \
                                    (hexlify(nonce).decode("ascii"), hexlify(self.job.nonce).decode("ascii")))
                        else:
                            # The nonce was correct. Wake up the main thread.
                            with self.wakeup:
                                self.checksuccess = True
                                self.wakeup.notify()

                elif result == 3:
                    # The device managed to process the whole 2**32 keyspace before we sent it new work.
                    self.core.log(self, "Exhausted keyspace!\n", 200, "y")
                    
                    # If it was a validation job, this probably means that there is a hardware/firmware bug
                    # or that the "found share" message was lost on the communication channel.
                    if isinstance(self.job, ValidationJob):
                        raise Exception("Validation job terminated without finding a share")
                    
                    # Stop measuring time because the device is doing duplicate work right now
                    self._jobend()
                    
                    # Wake up the main thread to fetch new work ASAP.
                    with self.wakeup:
                        self.wakeup.notify()
                    
                else:
                    # message from device was invalid or unexpected
                    raise Exception("Got bad message from mining device: %d" % result)
                    
        # If an exception is thrown in the listener thread...
        except Exception as e:
            # ...complain about it...
            self.core.log(self, "%s\n" % traceback.format_exc(), 100, "rB")
            
            # ...put it into the exception container...
            self.error = e
            
            # ...wake up the main thread...
            with self.wakeup:
                self.wakeup.notify()
            
            # ...and terminate the listener thread.

    def _sendjob(self, job):
        """Start the calculations on a job
        """
        self.nextjob = job
        

    def _old_sendjob(self, job):
        """Upload a job to the device
        """
        # Put it into nextjob. It will be moved to job by the listener
        # thread as soon as it gets acknowledged by the device.
        self.nextjob = job
        # Send it to the device
        self.handle.write(struct.pack("B", 1) + job.midstate[::-1] + job.data[75:63:-1])
        self.handle.flush()

    def _jobend(self, now=None):
        """Calculates work performed on the current job then destroys it
        Should be called whenever the device terminates its work
        """
        # Hack to avoid a python bug, don't integrate this into the line above
        if now is None:
            now = time.time()
        
        # Calculate how long the job was actually running and multiply that by the hash
        # rate to get the number of hashes calculated for that job and update statistics.
        if self.job is not None:
            if self.job.starttime is not None:
                self.job.hashes_processed(
                    (now - self.job.starttime) * self.stats.mhps * 1000000)
                self.job.starttime = None
            
            # helps count actual work performed on job and removes
            # it from cancellation lists
            self.job.destroy()
            self.job = None
