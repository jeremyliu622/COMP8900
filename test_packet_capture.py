import unittest
from unittest.mock import patch, MagicMock
from threading import Lock, Thread
from packet_capture import packet_callback, log_lock


class TestPacketCapture(unittest.TestCase):
    def setUp(self):
        # Mock arguments for filtering
        self.args = MagicMock()
        self.args.src_ip = None
        self.args.dest_ip = None
        self.args.ip = None
        self.args.protocol = None
        self.args.port = None

    @patch('packet_capture.logging.info')  # Mock logging to check log output
    def test_packet_logging(self, mock_logging):
        # Simulate an IP packet with necessary attributes
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet['IP'].src = '192.168.1.1'
        packet['IP'].dst = '192.168.1.2'
        packet.sprintf.return_value = 'TCP'

        # Call the callback function
        packet_callback(packet, self.args)

        # Assert logging was called with correct data
        mock_logging.assert_called_with("Source: 192.168.1.1, Destination: 192.168.1.2, Protocol: TCP")

    def test_src_ip_filtering(self):
        # Set source IP filter
        self.args.src_ip = '192.168.1.1'

        # Simulate a packet that doesn't match the source IP
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet['IP'].src = '10.0.0.1'
        packet['IP'].dst = '192.168.1.2'
        packet.sprintf.return_value = 'TCP'

        with patch('packet_capture.logging.info') as mock_logging:
            packet_callback(packet, self.args)

            # Ensure nothing was logged since the packet doesn't match
            mock_logging.assert_not_called()

    def test_protocol_filtering(self):
        # Set protocol filter
        self.args.protocol = 'UDP'

        # Simulate a TCP packet
        packet = MagicMock()
        packet.haslayer.return_value = True
        packet['IP'].src = '192.168.1.1'
        packet['IP'].dst = '192.168.1.2'
        packet.sprintf.return_value = 'TCP'

        with patch('packet_capture.logging.info') as mock_logging:
            packet_callback(packet, self.args)

            # Ensure nothing was logged since the packet doesn't match
            mock_logging.assert_not_called()

    def test_thread_safety(self):
        # Simulate multiple threads logging concurrently
        with patch('packet_capture.logging.info') as mock_logging:
            def log_in_thread():
                packet = MagicMock()
                packet.haslayer.return_value = True
                packet['IP'].src = '192.168.1.1'
                packet['IP'].dst = '192.168.1.2'
                packet.sprintf.return_value = 'TCP'
                packet_callback(packet, self.args)

            # Simulate 5 threads calling packet_callback
            threads = [Thread(target=log_in_thread) for _ in range(5)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            # Ensure all threads logged without corruption
            self.assertEqual(mock_logging.call_count, 5)

    def test_malformed_packet(self):
        # Simulate a malformed packet that raises an exception
        packet = MagicMock()
        packet.haslayer.side_effect = Exception("Malformed packet")

        with patch('packet_capture.logging.error') as mock_logging:
            packet_callback(packet, self.args)

            # Ensure error is logged
            mock_logging.assert_called_with("Error processing packet: Malformed packet")


if __name__ == '__main__':
    unittest.main()
