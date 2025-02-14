# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import

import functools
from collections import deque

from .base import BaseFormatter
from .process import strstatus
from ..handlers import SummaryHandler
import six
from functools import reduce


def output_subtests(func):
    @functools.wraps(func)
    def inner(self, data):
        if self.subtests_count:
            return self._format_subtests(data.get("component")) + func(self, data)
        else:
            return func(self, data)
    return inner


class TbplFormatter(BaseFormatter):
    """Formatter that formats logs in the legacy formatting format used by TBPL
    This is intended to be used to preserve backward compatibility with existing tools
    hand-parsing this format.
    """
    def __init__(self, compact=False, summary_on_shutdown=False, **kwargs):
        super(TbplFormatter, self).__init__(**kwargs)
        self.suite_start_time = None
        self.test_start_times = {}
        self.buffer = None
        self.compact = compact
        self.subtests_count = 0

        self.summary = SummaryHandler()
        self.summary_on_shutdown = summary_on_shutdown

    def __call__(self, data):
        if self.summary_on_shutdown:
            self.summary(data)
        return super(TbplFormatter, self).__call__(data)

    @property
    def compact(self):
        return self._compact

    @compact.setter
    def compact(self, value):
        self._compact = value
        if value:
            self.buffer = deque([], 10)
        else:
            self.buffer = None

    def _format_subtests(self, component, subtract_context=False):
        count = self.subtests_count
        if subtract_context:
            count -= len(self.buffer)
        self.subtests_count = 0
        return self._log({"level": "INFO",
                          "message": "." * count,
                          "component": component})

    @output_subtests
    def log(self, data):
        return self._log(data)

    def _log(self, data):
        if data.get('component'):
            message = "%s %s" % (data["component"], data["message"])
        else:
            message = data["message"]

        if "stack" in data:
            message += "\n%s" % data["stack"]

        return "%s\n" % message

    @output_subtests
    def process_output(self, data):
        pid = data['process']
        if pid.isdigit():
            pid = 'PID %s' % pid
        return "%s | %s\n" % (pid, data['data'])

    @output_subtests
    def process_start(self, data):
        msg = "TEST-INFO | started process %s" % data['process']
        if 'command' in data:
            msg = '%s (%s)' % (msg, data['command'])
        return msg + '\n'

    @output_subtests
    def process_exit(self, data):
        return "TEST-INFO | %s: %s\n" % (data['process'],
                                         strstatus(data['exitcode']))

    @output_subtests
    def crash(self, data):
        id = data["test"] if "test" in data else "pid: %s" % data["process"]

        signature = data["signature"] if data["signature"] else "unknown top frame"
        rv = ["PROCESS-CRASH | %s | application crashed [%s]" % (id, signature)]

        if data.get("minidump_path"):
            rv.append("Crash dump filename: %s" % data["minidump_path"])

        if data.get("stackwalk_stderr"):
            rv.append("stderr from minidump_stackwalk:")
            rv.append(data["stackwalk_stderr"])
        elif data.get("stackwalk_stdout"):
            rv.append(data["stackwalk_stdout"])

        if data.get("stackwalk_returncode", 0) != 0:
            rv.append("minidump_stackwalk exited with return code %d" %
                      data["stackwalk_returncode"])

        if data.get("stackwalk_errors"):
            rv.extend(data.get("stackwalk_errors"))

        rv = "\n".join(rv)
        if not rv[-1] == "\n":
            rv += "\n"

        return rv

    def suite_start(self, data):
        self.suite_start_time = data["time"]
        num_tests = reduce(lambda x, y: x + len(y), six.itervalues(data['tests']), 0)
        return "SUITE-START | Running %i tests\n" % num_tests

    def test_start(self, data):
        self.test_start_times[self.test_id(data["test"])] = data["time"]

        return "TEST-START | %s\n" % data["test"]

    def test_status(self, data):
        if self.compact:
            if "expected" in data:
                rv = []
                rv.append(self._format_subtests(data.get("component"), subtract_context=True))
                rv.extend(self._format_status(item) for item in self.buffer)
                rv.append(self._format_status(data))
                self.buffer.clear()
                return "".join(rv)
            else:
                self.subtests_count += 1
                self.buffer.append(data)
        else:
            return self._format_status(data)

    def assertion_count(self, data):
        if data["min_expected"] != data["max_expected"]:
            expected = "%i to %i" % (data["min_expected"],
                                     data["max_expected"])
        else:
            expected = "%i" % data["min_expected"]

        if data["count"] < data["min_expected"]:
            status, comparison = "TEST-UNEXPECTED-PASS", "is less than"
        elif data["count"] > data["max_expected"]:
            status, comparison = "TEST-UNEXPECTED-FAIL", "is more than"
        elif data["count"] > 0:
            status, comparison = "TEST-KNOWN-FAIL", "matches"
        else:
            return

        return ("%s | %s | assertion count %i %s expected %s assertions\n" %
                (status, data["test"], data["count"], comparison, expected))

    def _format_status(self, data):
        message = "- " + data["message"] if "message" in data else ""
        if "stack" in data:
            message += "\n%s" % data["stack"]
        if message and message[-1] == "\n":
            message = message[:-1]

        if "expected" in data:
            if not message:
                message = "- expected %s" % data["expected"]
            failure_line = "TEST-UNEXPECTED-%s | %s | %s %s\n" % (
                data["status"], data["test"], data["subtest"],
                message)
            if data["expected"] != "PASS":
                info_line = "TEST-INFO | expected %s\n" % data["expected"]
                return failure_line + info_line
            return failure_line

        return "TEST-%s | %s | %s %s\n" % (
            data["status"], data["test"], data["subtest"],
            message)

    def test_end(self, data):
        rv = []
        if self.compact and self.subtests_count:
            print_context = "expected" in data
            rv.append(self._format_subtests(data.get("component"),
                                            subtract_context=print_context))
            if print_context:
                rv.extend(self._format_status(item) for item in self.buffer)
            self.buffer.clear()

        test_id = self.test_id(data["test"])
        duration_msg = ""

        if test_id in self.test_start_times:
            start_time = self.test_start_times.pop(test_id)
            time = data["time"] - start_time
            duration_msg = "took %ims" % time

        if "expected" in data:
            message = data.get("message", "")
            if not message:
                message = "expected %s" % data["expected"]
            if "stack" in data:
                message += "\n%s" % data["stack"]
            if message and message[-1] == "\n":
                message = message[:-1]

            extra = data.get("extra", {})
            if "reftest_screenshots" in extra:
                screenshots = extra["reftest_screenshots"]
                if len(screenshots) == 3:
                    message += ("\nREFTEST   IMAGE 1 (TEST): data:image/png;base64,%s\n"
                                "REFTEST   IMAGE 2 (REFERENCE): data:image/png;base64,%s") % (
                                    screenshots[0]["screenshot"],
                                    screenshots[2]["screenshot"])
                elif len(screenshots) == 1:
                    message += "\nREFTEST   IMAGE: data:image/png;base64,%s" \
                               % screenshots[0]["screenshot"]

            failure_line = "TEST-UNEXPECTED-%s | %s | %s\n" % (
                data["status"], test_id, message)

            if data["expected"] not in ("PASS", "OK"):
                expected_msg = "expected %s | " % data["expected"]
            else:
                expected_msg = ""
            info_line = "TEST-INFO %s%s\n" % (expected_msg, duration_msg)

            return failure_line + info_line

        sections = ["TEST-%s" % data['status'], test_id]
        if duration_msg:
            sections.append(duration_msg)
        rv.append(' | '.join(sections) + '\n')
        return "".join(rv)

    def suite_end(self, data):
        start_time = self.suite_start_time
        time = int((data["time"] - start_time) / 1000)

        return "SUITE-END | took %is\n" % time

    def test_id(self, test_id):
        if isinstance(test_id, (str, six.text_type)):
            return test_id
        else:
            return tuple(test_id)

    @output_subtests
    def valgrind_error(self, data):
        rv = "TEST-UNEXPECTED-VALGRIND-ERROR | " + data['primary'] + "\n"
        for line in data['secondary']:
            rv = rv + line + "\n"

        return rv

    def lint(self, data):
        fmt = "TEST-UNEXPECTED-{level} | {path}:{lineno}{column} | {message} ({rule})"
        data["column"] = ":%s" % data["column"] if data["column"] else ""
        data['rule'] = data['rule'] or data['linter'] or ""
        return fmt.append(fmt.format(**data))

    def _format_suite_summary(self, suite, summary):
        counts = summary['counts']
        logs = summary['unexpected_logs']

        total = sum(self.summary.aggregate('count', counts).values())
        expected = sum(self.summary.aggregate('expected', counts).values())
        status_str = "{}/{}".format(expected, total)
        rv = ["{}: {}".format(suite, status_str)]

        for results in logs.values():
            for data in results:
                rv.append("  {}".format(self._format_status(data)))
        return "\n".join(rv)

    def shutdown(self, data):
        if not self.summary_on_shutdown:
            return

        rv = ["", "Overall Summary"]
        for suite, summary in self.summary:
            rv.append(self._format_suite_summary(suite, summary))
        rv.append("")
        return "\n".join(rv)
