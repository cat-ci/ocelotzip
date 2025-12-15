# Ocelot.Zip

Simple personal file host with on-the-fly image/audio/video processing, per-user storage, and short slugs.

## Features

- Per-user upload directory under `uploads/<username>`
- User account metadata stored in `accounts/<username>.json` and slug maps in `accounts/<username>.slugs.json`
- Web UI file manager (`public/filemanager.html`) for browsing, uploading, creating folders, renaming and deleting
- Short slug URLs for files (6-character alphanumeric)
- Pretty and timestamp-based URLs for file access
- On-demand processing for images, audio and video (resizing, format conversion, quality, etc.) with caching in `temp/`
- Package API to create ZIP archives of multiple files (with optional transformations)

## Quick start

Install dependencies and start the server:

```bash
npm install
npm start
```

Open `http://localhost:3000` and log in via the configured OAuth provider (set to `http://localhost:4000` in `server.js` by default).

Uploaded files are saved under `uploads/<username>` and temporary processed files are written to `temp/`.

## Important paths

- Uploads: `uploads/`
- Accounts: `accounts/` (per-user JSON and slug maps)
- Temp cache: `temp/`
- Public UI: `public/`

## API Endpoints

All JSON endpoints are mounted on `http://localhost:3000` by default.

- `GET /api/files?path=<path>`
	- Authenticated. Lists files and folders in the user's directory (relative `path` optional).
	- Response includes `items` with `{ name, originalName, slug, isDir, size, mtime, path, url }`.

- `POST /api/upload?path=<path>`
	- Authenticated. Multipart form upload with field `file`.
	- Saves file to the user's folder. Returns `{ success, slug, timestamp, original }` where `timestamp` is the relative path for the saved file.

- `POST /api/folder`
	- Authenticated. Body `{ path, name }` creates a new folder inside the user's directory.

- `POST /api/move`
	- Authenticated. Body `{ from, to }` moves a file or folder (paths are relative to the user's root).

- `POST /api/rename`
	- Authenticated. Body `{ path, newName }` renames a file or folder.

- `POST /api/delete`
	- Authenticated. Body `{ path }` deletes a file or folder.

- `GET /api/apikey`
	- Returns the user's API key when logged in via session.

- `POST /api/package`
	- Creates a ZIP package of multiple files with optional per-file transformation parameters.
	- Body: `{ username, files: [ { path, ...params } ] }` where `path` is relative to the user's root. Responds with a downloadable ZIP.

## File access URLs

- Slug: `/files/<username>/<slug>` (6-character slug)
- Pretty name: `/files/<username>/<original>` (resolver will search user's files)
- Timestamp / direct: `/files/<username>/<relative/path/to/timestamp-filename>` (recommended for nested files)

Examples of transform parameters (query string on file routes):
- Images: `?w=800&h=600&f=webp&q=80&s=cover`
- Audio: `?f=mp3&q=192`
- Video: `?w=1280&h=720&f=mp4`

## Notes

- Slug mappings are stored per-user in `accounts/<username>.slugs.json`. The server stores the slug -> relative-path mapping so slugs work for files in subfolders.
- If you previously had slugs stored as bare filenames, duplicates across folders may cause ambiguity; consider migrating slug maps to use relative paths.
- Temporary processed files are cleaned up automatically (older than 28 days).

## Contributing / Development

- The server is in `server.js`. Image/audio/video processing hooks are in `modules/` (`imageProcessor.js`, `audioProcessor.js`, `videoProcessor.js`).
- To add new transformations, update the corresponding `process` function in `modules/` and the parameter handling in `server.js`.