"""
WiFi Security Monitoring Module

This module provides functions to detect and respond to WiFi attacks including
deauthentication attacks and WPS brute force attempts.

Usage as a module:
    from wifi import WiFiMonitor
    
    monitor = WiFiMonitor("wlan0")
    monitor.start_deauth_detection()
    monitor.start_wps_detection()
    # ... do other work ...
    monitor.stop_all()

Usage as a standalone script:
    python wifi.py <interface>
"""

from detect_deauth import detect_deauth
from detect_wps_bf import detect_wps_brute_force
import threading
import argparse
import time


class WiFiMonitor:
    """WiFi security monitoring system that detects attacks"""
    
    def __init__(self, interface, deauth_callback=None, wps_callback=None):
        """
        Initialize WiFi monitor
        
        Args:
            interface: Network interface to monitor (e.g., 'wlan0')
            deauth_callback: Optional callback function for deauth attacks
            wps_callback: Optional callback function for WPS attacks
        """
        self.interface = interface
        self.deauth_callback = deauth_callback or self._default_deauth_handler
        self.wps_callback = wps_callback or self._default_wps_handler
        
        self.deauth_thread = None
        self.wps_thread = None
        self._stop_event = threading.Event()
    
    def _default_deauth_handler(self, attack_info):
        """Default handler for detected deauthentication attack"""
        print(f"\n>>> ACTION: Responding to deauth attack from {attack_info['attacker_mac']}")
        print(f">>> Target AP: {attack_info['target_ap']}")
        print(f">>> Affected devices: {attack_info['all_macs']}")
        
        # - Set up fake AP with set password
        # - Send fake deauth packets to give attacker "hashes" they can crack
    
    def _default_wps_handler(self, attack_info):
        """Default handler for detected WPS brute force attack"""
        print(f"\n>>> ACTION: Responding to WPS brute force from {attack_info['attacker_mac']}")
        print(f">>> Target AP: {attack_info['target_ap']}")
        print(f">>> Involved devices: {attack_info['all_macs']}")
        
        # - Set up fake WPS AP to trap attacker
        # - Make the PIN easy to guess, honeypot continues
    
    def start_deauth_detection(self):
        """Start deauthentication attack detection thread"""
        if self.deauth_thread and self.deauth_thread.is_alive():
            print("Deauth detection is already running")
            return False
        
        self.deauth_thread = threading.Thread(
            target=detect_deauth,
            args=(self.interface, self.deauth_callback),
            daemon=True,
            name="DeauthDetector"
        )
        self.deauth_thread.start()
        print(f"Started deauth detection on {self.interface}")
        return True
    
    def start_wps_detection(self):
        """Start WPS brute force detection thread"""
        if self.wps_thread and self.wps_thread.is_alive():
            print("WPS detection is already running")
            return False
        
        self.wps_thread = threading.Thread(
            target=detect_wps_brute_force,
            args=(self.interface, self.wps_callback),
            daemon=True,
            name="WPSDetector"
        )
        self.wps_thread.start()
        print(f"Started WPS detection on {self.interface}")
        return True
    
    def start_all(self):
        """Start both deauth and WPS detection threads"""
        deauth_started = self.start_deauth_detection()
        wps_started = self.start_wps_detection()
        return deauth_started or wps_started
    
    def stop_deauth_detection(self):
        """Stop deauthentication attack detection"""
        if self.deauth_thread and self.deauth_thread.is_alive():
            print("Stopping deauth detection...")
            # Note: daemon threads will stop when main program exits
            # For graceful shutdown, detection functions should check a stop event
            self.deauth_thread = None
            return True
        return False
    
    def stop_wps_detection(self):
        """Stop WPS brute force detection"""
        if self.wps_thread and self.wps_thread.is_alive():
            print("Stopping WPS detection...")
            self.wps_thread = None
            return True
        return False
    
    def stop_all(self):
        """Stop all detection threads"""
        self._stop_event.set()
        self.stop_deauth_detection()
        self.stop_wps_detection()
        print("All detection stopped")
    
    def is_deauth_running(self):
        """Check if deauth detection is running"""
        return self.deauth_thread is not None and self.deauth_thread.is_alive()
    
    def is_wps_running(self):
        """Check if WPS detection is running"""
        return self.wps_thread is not None and self.wps_thread.is_alive()
    
    def status(self):
        """Get status of all detection threads"""
        return {
            'interface': self.interface,
            'deauth_running': self.is_deauth_running(),
            'wps_running': self.is_wps_running()
        }


# Convenience functions for simple use cases
def start_monitoring(interface, deauth_callback=None, wps_callback=None):
    """
    Start WiFi monitoring on the specified interface
    
    Args:
        interface: Network interface to monitor
        deauth_callback: Optional callback for deauth attacks
        wps_callback: Optional callback for WPS attacks
    
    Returns:
        WiFiMonitor instance
    """
    monitor = WiFiMonitor(interface, deauth_callback, wps_callback)
    monitor.start_all()
    return monitor


def main():
    """Main entry point for standalone usage"""
    parser = argparse.ArgumentParser(description="WiFi security monitoring system")
    parser.add_argument("interface", type=str, help="Network interface to monitor")
    args = parser.parse_args()
    
    # Create and start monitor
    monitor = WiFiMonitor(args.interface)
    monitor.start_all()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        monitor.stop_all()

if __name__ == "__main__":
    main()
