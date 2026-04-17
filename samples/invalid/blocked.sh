#!/bin/bash
# This file has a .sh extension and should be rejected by the upload endpoint.
#
# Expected response:
#   HTTP 422 Unprocessable Entity
#   { "error": "File type not allowed: .sh" }
#
# Shell scripts are blocked regardless of content.

echo "This should never be executed via the application."
