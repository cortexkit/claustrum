import { OUR_PLUGIN_ID } from "./handles";
import type { Plugin } from "./v2/host-types";

const setup: Plugin["setup"] = () => () => {};

export default { id: OUR_PLUGIN_ID, setup } satisfies Plugin;
