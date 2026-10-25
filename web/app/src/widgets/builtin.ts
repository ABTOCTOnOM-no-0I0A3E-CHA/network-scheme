import { deviceStatusWidget } from "./deviceStatus";
import { logStreamWidget } from "./logStream";
import { metricChartWidget } from "./metricChart";
import { miniMapWidget } from "./miniMapWidget";
import { problemsWidget } from "./problems";
import { recentChangesWidget } from "./recentChanges";
import { registerWidget } from "./registry";
import { topDevicesWidget } from "./topDevices";
import { topInterfacesWidget } from "./topInterfaces";

/* The FR-DASH-3 widgets, in catalog order. A new widget is one more registration here (and its type on the server). */
registerWidget(deviceStatusWidget);
registerWidget(problemsWidget);
registerWidget(topDevicesWidget);
registerWidget(logStreamWidget);
registerWidget(metricChartWidget);
registerWidget(topInterfacesWidget);
registerWidget(recentChangesWidget);
registerWidget(miniMapWidget);
