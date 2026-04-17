Invalid sample files — expected to be REJECTED by the upload endpoint.

blocked.exe
  Extension: .exe (in BLOCKED_EXTENSIONS set)
  Expected: 422 Unprocessable Entity — "File type not allowed: .exe"

blocked.sh
  Extension: .sh (in BLOCKED_EXTENSIONS set)
  Expected: 422 Unprocessable Entity — "File type not allowed: .sh"

Other blocked extensions (not included as files):
  .bat .cmd .ps1 .vbs .jar .msi .dll .scr .com

Zip bomb (cannot be committed safely):
  A real zip bomb is a zip file with a very high compression ratio.
  The FileSecurityServiceTest.zipBombByRatio_throwsFileSecurityException test
  generates one programmatically and verifies the 422 response.
  Threshold: uncompressed/compressed ratio > 100 OR uncompressed > 500 MB.
