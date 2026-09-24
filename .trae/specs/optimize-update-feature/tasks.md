# Tasks

- [x] Task 1: Enhance ParseBaiduDownloadInfo method in UpdateCheckService.cs
  - [x] SubTask 1.1: Support multiple Baidu URL formats (?pwd=xxx, 链接：, 下载链接:, etc.)
  - [x] SubTask 1.2: Support multiple extraction code formats (提取码, 密码, ?pwd=)
  - [x] SubTask 1.3: Handle cases where code is in URL but not in text
  - [x] SubTask 1.4: Add comprehensive regex patterns with proper fallbacks

- [x] Task 2: Optimize UpdateDialog UI/UX
  - [x] SubTask 2.1: Add prompt text "📥 点击下方蓝色链接在浏览器中打开百度网盘页面" for better visibility
  - [x] SubTask 2.2: Improve Baidu URL text styling (blue color, semi-bold, underline)
  - [x] SubTask 2.3: Ensure extraction code is prominent and easy to copy
  - [x] SubTask 2.4: Add "复制全部" button to copy both URL and code together

- [x] Task 3: Add version validation on download
  - [x] SubTask 3.1: Verify downloaded package version matches expected version (ValidateDownloadedVersion)
  - [x] SubTask 3.2: Show warning if version mismatch detected
  - [x] SubTask 3.3: Add file size validation (minimum 1MB)

- [ ] Task 4: Test and verify update flow end-to-end
  - [ ] SubTask 4.1: Build and test with mock GitHub release data
  - [ ] SubTask 4.2: Verify Baidu URL parsing with various formats
  - [ ] SubTask 4.3: Test update dialog display and interactions
  - [ ] SubTask 4.4: Confirm compilation with 0 errors

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 1
- Task 4 depends on Task 1, 2, 3