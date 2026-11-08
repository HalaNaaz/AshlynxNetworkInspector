import csv
import io
from typing import Any

from backend.app.reports.data_collector import ReportPayload


class CsvReportGenerator:
    """Exports structured tabular data adhering strictly to RFC 4180 CSV specifications.

    Features:
    - Exactly one consistent header row
    - Consistent column count across all lines
    - Spreadsheet formula injection protection (=, +, -, @, tab, CR prefix sanitization)
    - Source data only (no metadata comments or blank lines)
    - Full compatibility with Python csv.reader and pandas.read_csv()
    """

    @staticmethod
    def _sanitize_cell(value: Any) -> str:
        """Sanitizes cell contents against spreadsheet formula injection."""
        if value is None:
            return ""
        text = str(value)
        # Formula trigger characters in Excel/LibreOffice/Google Sheets
        if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
            return f"'{text}"
        return text

    @classmethod
    def generate(cls, payload: ReportPayload) -> bytes:
        output = io.StringIO()
        writer = csv.writer(
            output,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\r\n",
        )

        # 1. Single authoritative header row
        sanitized_headers = [cls._sanitize_cell(h) for h in payload.table_headers]
        writer.writerow(sanitized_headers)

        # 2. Source data rows with consistent column count
        expected_cols = len(payload.table_headers)
        for row in payload.table_rows:
            cleaned_row = [cls._sanitize_cell(col) for col in row]
            # Ensure consistent column count
            if len(cleaned_row) < expected_cols:
                cleaned_row.extend([""] * (expected_cols - len(cleaned_row)))
            elif len(cleaned_row) > expected_cols:
                cleaned_row = cleaned_row[:expected_cols]
            writer.writerow(cleaned_row)

        return output.getvalue().encode("utf-8")
