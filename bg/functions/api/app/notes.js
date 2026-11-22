// GET /api/app/notes  (headers: x-app-key, x-device-id)
import { appHandler } from "../../_lib/common.js";
export const onRequest = ({ request, env }) => appHandler(request, env, "notes");
