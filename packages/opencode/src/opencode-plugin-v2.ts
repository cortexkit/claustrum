import { OUR_PLUGIN_ID } from "./handles";
import type { Plugin } from "./v2/host-types";
import { createOpencodeClaustrumPluginV2 } from "./v2/setup";

const setup = createOpencodeClaustrumPluginV2();

export default { id: OUR_PLUGIN_ID, setup } satisfies Plugin;
