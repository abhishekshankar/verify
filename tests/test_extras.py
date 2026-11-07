import os, subprocess, sys, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))


def run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=60)


class Extras(unittest.TestCase):
    def test_mcp_selftest(self):
        from verify import mcp_server
        mcp_server._selftest()

    def test_mcp_stdio(self):
        p = run("-m", "verify.mcp_server", "--selftest")
        self.assertEqual(p.returncode, 0, p.stderr)
        inp = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
        p = subprocess.run([sys.executable, "-m", "verify.mcp_server"], input=inp, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=30)
        self.assertEqual(len(p.stdout.splitlines()), 2, p.stderr)
        self.assertIn('"2025-06-18"', p.stdout)

    def test_examples(self):
        cases = [("plain_cron.py", "--demo", 1), ("plain_cron.py", "--demo-good", 0), ("claude_agent_sdk.py", None, 0),
                 ("openai_agents_sdk.py", None, 0), ("langgraph_node.py", None, 0)]
        for script, arg, code in cases:
            with self.subTest(script=script, arg=arg):
                p = run(os.path.join("examples", script), *([arg] if arg else []))
                self.assertEqual(p.returncode, code, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
