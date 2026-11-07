# Running and interpreting tests

Use a source environment with the application's dependencies. From PowerShell in the repository root:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
py -3.12 tests/test_time_window.py
py -3.12 tests/test_csv_formula_safe.py
```

These are standalone scripts, not a requirement to invoke pytest. Check the subprocess return code **and** the assertions/counts printed. Some tests have optional real-input sections and can return success while those sections were skipped.

## Suite runner

```powershell
py -3.12 tests/run_suite.py
```

The runner discovers tests/test_*.py, sorts filenames and runs each file in a separate subprocess from the repository root. It sets QT_QPA_PLATFORM=offscreen and PYTHONIOENCODING=utf-8, with a **900-second per-file timeout**. It reports OK/FAIL for files, includes the last 25 output lines of failures in its log, and exits zero only if all discovered files exit zero.

The default log is eventhawk_suite.txt under the system temporary directory. An optional **positional** argument chooses the log path:

```powershell
py -3.12 tests/run_suite.py .\suite-results.txt
```

There is no --help parser: a supplied --help would be treated as the output filename and start the suite. Do not use that as a discovery command.

EVTX_TEST_LOGS and EVTX_TEST_LOGS_ONLINE optionally identify local test-log directories. Relevant real-log sections can skip when they are absent. Setting them does not make every test a complete forensic oracle. Sentinel also has tests under sentinel/tests; the top-level runner's glob does not recursively include that directory.

## Output verification

For a meaningful regression check, reproduce the trigger and inspect the generated result, not merely a button click or exit zero. Compare event identities/counts with an independent reader or raw record headers, account for source files and copies, inspect warnings/skips, and validate exported files in their actual format. Synthetic controls should distinguish different providers, missing fields, duplicate occurrences and boundary times.

Keep collected logs and derived evidence private. Publish synthetic examples, counts and code facts rather than identifying event values. Performance observations must state collection scope, selected operations and measurement limits; a functional pass does not establish a RAM/latency guarantee.
