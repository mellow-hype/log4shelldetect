# detect-log4shell+sha256

**Adds functionality to compares the SHA256 of the file against those of known vulnerable versions of log4j-core.**

Scans a file or folder recursively for Java programs that may be vulnerable to Log4Shell (CVE-2021-44228) by inspecting the class paths inside files.

If you only want possibly vulnerable files to be printed rather than all files, run with `-mode list`.

## Usage

```
Usage: log4shelldetect [options] <path>

Options:
  -mode string
        the output mode, either "report" (every jar pretty printed) or "list" (list of potentially vulnerable files) (default "report")
```

## License

Code here is released to the public domain under [unlicense](/LICENSE).
