# Deploying MalSandbox ML to Hugging Face Spaces

1. Create a new Hugging Face Space and choose **Docker** as the SDK.
2. Upload/push the contents of this folder to the Space repository.
3. Hugging Face reads the README YAML and exposes the app on port **7860**.
4. Wait for the Space build to finish, then open the Space URL.

No Redis server is required for this hosted demo: `LOCAL_MODE=1` uses the project's in-memory queue.
No Docker socket is required: the hosted version intentionally uses the project's sandbox simulation fallback.

## Important distinction

The Hugging Face Space is a portfolio/demo deployment of the ML pipeline. It is not the production dynamic-execution sandbox. The original project should be used when you need real Docker + Playwright isolation.
