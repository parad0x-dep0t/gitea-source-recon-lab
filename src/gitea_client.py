"""
gitea_client.py

Client library for interacting with Gitea REST API.
Handles repository discovery, enumeration, and archive extraction.
"""

import os
import io
import shutil
import zipfile
import requests


class GiteaClient:
    def __init__(self, base_url, token=None, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.timeout = timeout
        self.headers = {}

        if token:
            self.headers["Authorization"] = f"token {token}"

    def list_repositories(self):
        """
        List repositories accessible to the user or public repositories.
        """
        url = f"{self.api_url}/user/repos" if "Authorization" in self.headers else f"{self.api_url}/repos/search"

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise RuntimeError(f"Network error connecting to Gitea at {self.base_url}: {e}")

        if response.status_code != 200:
            raise RuntimeError(f"Failed to list repositories (HTTP {response.status_code}): {response.text}")

        data = response.json()

        # Authenticated returns list directly
        if isinstance(data, list):
            return data

        # Unauthenticated search returns wrapped object { "data": [...] }
        return data.get("data", [])

    def download_repo(self, owner, repo_name, destination_dir="tmp_repos"):
        """
        Download repository using its default branch ZIP archive and extract it.
        """
        # Step 1: Get repository metadata for default branch
        repo_info_url = f"{self.api_url}/repos/{owner}/{repo_name}"
        try:
            response = requests.get(repo_info_url, headers=self.headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise RuntimeError(f"Network error fetching repository metadata for {owner}/{repo_name}: {e}")

        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch metadata for {owner}/{repo_name} (HTTP {response.status_code}): {response.text}")

        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")

        # Step 2: Download archive
        archive_url = f"{self.api_url}/repos/{owner}/{repo_name}/archive/{default_branch}.zip"
        try:
            archive_response = requests.get(archive_url, headers=self.headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise RuntimeError(f"Network error downloading archive from {archive_url}: {e}")

        if archive_response.status_code != 200:
            raise RuntimeError(f"Failed to download repository archive (HTTP {archive_response.status_code}): {archive_response.text}")

        os.makedirs(destination_dir, exist_ok=True)

        # Step 3: Extract ZIP
        with zipfile.ZipFile(io.BytesIO(archive_response.content)) as z:
            namelist = z.namelist()
            if not namelist:
                raise ValueError("Downloaded archive is empty.")

            top_level_folder = namelist[0].split("/")[0]
            extract_path = os.path.join(destination_dir, top_level_folder)

            # Clean re-run
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path, ignore_errors=True)

            z.extractall(destination_dir)

        return extract_path
