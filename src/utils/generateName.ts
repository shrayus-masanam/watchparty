import { serverPath } from "./utils";

export async function generateName(): Promise<string> {
  const response = await fetch(serverPath + "/generateRandomName");
  return response.text();
}
