import requests
import zipfile
import io
import os

class GiteaClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.headers = {}

        if token:
            self.headers["Authorization"] = f"token {token}"

    def list_repositories(self):
        """
        List repositories accessible to the user.
        Works for both authenticated and unauthenticated access.
        """
        url = f"{self.api_url}/user/repos" if self.headers else f"{self.api_url}/repos/search"

        response = requests.get(url, headers=self.headers)

        if response.status_code != 200:
            raise Exception(f"Failed to list repositories: {response.text}")

        data = response.json()

        # Authenticated returns list directly
        if isinstance(data, list):
            return data

        # Unauthenticated search returns wrapped object
        return data.get("data", [])

    def download_repo(self, owner, repo_name):
        """
        Download repository using its default branch
        and avoid double-folder extraction.
        """

        # Step 1: Get repository metadata
        repo_info_url = f"{self.api_url}/repos/{owner}/{repo_name}"
        response = requests.get(repo_info_url, headers=self.headers)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch repo metadata: {response.text}")

        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")

        print(f"    -> Default branch: {default_branch}")

        # Step 2: Download archive
        archive_url = f"{self.api_url}/repos/{owner}/{repo_name}/archive/{default_branch}.zip"
        archive_response = requests.get(archive_url, headers=self.headers)

        if archive_response.status_code != 200:
            raise Exception(f"Failed to download repo archive: {archive_response.text}")

        # Ensure tmp folder exists
        base_tmp_path = "tmp_repos"
        os.makedirs(base_tmp_path, exist_ok=True)

        # Extract ZIP in memory
        with zipfile.ZipFile(io.BytesIO(archive_response.content)) as z:

            # Detect top-level folder name inside ZIP
            top_level_folder = z.namelist()[0].split("/")[0]

            extract_path = os.path.join(base_tmp_path, top_level_folder)

            # Remove existing folder if already present (clean re-run)
            if os.path.exists(extract_path):
                import shutil
                shutil.rmtree(extract_path)

            z.extractall(base_tmp_path)

        return extract_path

