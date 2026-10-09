import unittest
from app import detect
class DetectionTests(unittest.TestCase):
 def test_high_rate(self): self.assertIn("NET-001",[a["rule"] for a in detect({"connections_last_minute":100})])
 def test_unusual_port(self): self.assertIn("NET-002",[a["rule"] for a in detect({"dst_port":4444})])
 def test_failed_connections(self): self.assertIn("NET-003",[a["rule"] for a in detect({"failed_connections":20})])
 def test_normal_flow_quiet(self): self.assertEqual(detect({"dst_port":443,"connections_last_minute":3,"failed_connections":0}),[])
 def test_invalid_counter(self):
  with self.assertRaises(ValueError): detect({"connections_last_minute":-1})
if __name__=="__main__": unittest.main()
