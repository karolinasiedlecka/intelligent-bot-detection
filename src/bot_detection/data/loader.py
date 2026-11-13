import csv
from pathlib import Path


def load_access_logs(file_path):
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        logs = list(reader)

    return logs


def main():
    project_root = Path(__file__).resolve().parents[3]

    file_path = (
        project_root
        / "data"
        / "samples"
        / "sample_access_logs.csv"
    )

    logs = load_access_logs(file_path)

    print(f"Loaded {len(logs)} HTTP requests")

    for log in logs:
        print(log)


if __name__ == "__main__":
    main()