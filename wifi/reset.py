import serial
import time
import random
# Configure the serial port parameters
# Replace 'COM4' with your port name (e.g., '/dev/ttyUSB0' on Linux or 'COM1' on Windows)
# Replace 9600 with the baud rate required by your device
ser = serial.Serial(
    port='COM3',
    baudrate=9600,
    bytesize=serial.EIGHTBITS,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    timeout=1 # Set a timeout (in seconds)
)
x = random.randint(0,100)
try:
    # Wait a moment for the connection to establish
    time.sleep(.1)

    if ser.is_open:
        print(f"Serial port {ser.port} opened successfully.")

        # Data must be sent as bytes. Encode the string to bytes.
        waiting = '\n'
        data_to_send = f'e\w\\a code{x} 1234 0 0' # The 'b' prefix creates a bytes object
        # Alternatively, use: data_to_send = bytes('Hello, world!\n', 'utf-8')
        ser.write(waiting.encode('utf-8'))
        ser.write(waiting.encode('utf-8'))
        time.sleep(0.3) # Wait for device to respond
        ser.write(data_to_send.encode('utf-8'))
        ser.write(waiting.encode('utf-8'))
        #ser.write(data_to_send.encode('utf-8'))
        print(f"Sent data: {data_to_send}")

        # Optional: Read response
        time.sleep(0.1) # Wait for device to respond
        if ser.in_waiting > 0:
            response = ser.readline().decode('utf-8').strip()
            print(f"Received response: {response}")
    else:
        print("Failed to open serial port.")

except serial.SerialException as e:
    print(f"Error: {e}")

finally:
    # Always close the port when done to free the resource
    if ser.is_open:
        ser.close()
        print(f"Serial port {ser.port} closed.")
