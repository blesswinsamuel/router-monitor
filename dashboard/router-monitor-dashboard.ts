import { Dashboard, DashboardCursorSync, DataSourceRef, LegendDisplayMode, MappingType, TableCellHeight, ThresholdsMode, VizOrientation, defaultDashboard } from '@grafana/schema'
import {
  NewBarGaugePanel,
  NewPanelGroup,
  NewPanelRow,
  NewPieChartPanel,
  NewPrometheusDatasource as NewPrometheusDatasourceVariable,
  NewQueryVariable,
  NewStatPanel,
  NewTablePanel,
  NewTimeSeriesPanel,
  PanelRow,
  PanelRowAndGroups,
  Unit,
  autoLayout,
  writeDashboardAndPostToGrafana,
} from 'grafana-dashboard-helpers'

const datasource: DataSourceRef = {
  uid: '${DS_PROMETHEUS}',
}

const totalBytesByLocalIPQuery = (labels: string, ipLabel: string) => `
label_replace(
  sum by(${ipLabel}) (
    increase(
      router_monitor_bytes_total{${labels},instance=~"$instance"}[$__range]
    ) > 0
  ),
  "ip", "$1", "${ipLabel}", "(.*)"
)

+ on(ip) group_left(devicename)

(0 * max(router_monitor_dnsmasq_lease_info) by (devicename, ip, mac))
`

const totalBytesByLocalIPPieChartPanel = (uploadOrDownload: string, labels: string, ipLabel: string) =>
  NewPieChartPanel({
    title: `Total Bytes ${uploadOrDownload}ed - by local IP (pie chart)`,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel), legendFormat: '{{ devicename }} ({{ ip }})', type: 'instant' }],
    defaultUnit: Unit.BYTES_SI,
  })

const totalBytesByLocalIPBarGaugePanel = (uploadOrDownload: string, labels: string, ipLabel: string) =>
  NewBarGaugePanel({
    title: `Total Bytes ${uploadOrDownload}ed - by local IP (bar gauge)`,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel), legendFormat: '{{ devicename }} ({{ ip }})', type: 'instant' }],
    defaultUnit: Unit.BYTES_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    options: { orientation: VizOrientation.Horizontal },
  })

const totalBytesTimeSeriesPanel = (title: string, labels: string, ipLabel: string) =>
  NewTimeSeriesPanel({
    title: title,
    targets: [{ expr: `sum by(${ipLabel}) (increase(router_monitor_bytes_total{${labels},instance=~"$instance"}[$__interval] > 0))`, legendFormat: `{{ ${ipLabel} }}` }],
    defaultUnit: Unit.BYTES_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    type: 'bar',
    options: { legend: { calcs: ['sum'], placement: 'bottom' } },
  })

const dataRateTimeSeriesPanel = (title: string, labels: string, ipLabel: string) =>
  NewTimeSeriesPanel({
    title,
    targets: [{ expr: `sum by(${ipLabel}) (rate(router_monitor_bytes_total{${labels},instance=~"$instance"}[$__rate_interval] > 0))`, legendFormat: `{{ ${ipLabel} }}` }],
    defaultUnit: Unit.BYTES_PER_SEC_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    options: { legend: { calcs: ['sum'], placement: 'bottom' } },
  })

const networkTrafficPanels: PanelRow[] = [
  NewPanelRow({ datasource, height: 12 }, [
    // prettier hack
    totalBytesByLocalIPPieChartPanel('Download', 'dst=~"$localips",src=~"internet"', 'dst'),
    totalBytesByLocalIPPieChartPanel('Upload', 'src=~"$localips",dst=~"internet"', 'src'),
  ]),
  NewPanelRow({ datasource, height: 12 }, [
    // prettier hack
    totalBytesByLocalIPBarGaugePanel('Download', 'dst=~"$localips",src=~"internet"', 'dst'),
    totalBytesByLocalIPBarGaugePanel('Upload', 'src=~"$localips",dst=~"internet"', 'src'),
  ]),
  NewPanelRow({ datasource, height: 12 }, [
    // prettier hack
    totalBytesTimeSeriesPanel('Total bytes downloaded - by local IP', 'dst=~"$localips",src=~"internet"', 'dst'),
    totalBytesTimeSeriesPanel('Total bytes uploaded - by local IP', 'src=~"$localips",dst=~"internet"', 'src'),
    dataRateTimeSeriesPanel('Download Data Rate - by local IP', 'dst=~"$localips",src=~"internet"', 'dst'),
    dataRateTimeSeriesPanel('Upload Data Rate - by local IP', 'src=~"$localips",dst=~"internet"', 'src'),
  ]),
  NewPanelRow({ datasource, height: 10 }, [
    // prettier hack
    totalBytesTimeSeriesPanel('Total bytes downloaded', 'dst=~"$localips",src=~"internet"', 'src'),
    totalBytesTimeSeriesPanel('Total bytes uploaded', 'src=~"$localips",dst=~"internet"', 'dst'),
    dataRateTimeSeriesPanel('Download Data Rate', 'dst=~"$localips",src=~"internet"', 'src'),
    dataRateTimeSeriesPanel('Upload Data Rate', 'src=~"$localips",dst=~"internet"', 'dst'),
  ]),
]

const panels: PanelRowAndGroups = [
  NewPanelGroup({ title: 'Overview' }, [
    NewPanelRow({ datasource, height: 3 }, [
      NewStatPanel({
        title: 'Internet',
        targets: [{ expr: 'router_monitor_internet_connection_is_up{instance=~"$instance"}' }],
        defaultUnit: Unit.SHORT,
        mappings: [{ options: { '0': { text: 'Down' }, '1': { text: 'Up' } }, type: MappingType.ValueToText }],
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'red', value: null },
            { color: 'green', value: 1 },
          ],
        },
      }),
      NewStatPanel({
        title: 'Internet Downtime',
        targets: [{ expr: '(1 - avg_over_time(router_monitor_internet_connection_is_up{instance=~"$instance"}[$__range])) * $__range_s' }],
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'green', value: null },
            { color: 'red', value: 1 },
          ],
        },
        defaultUnit: Unit.SECONDS,
      }),
      NewStatPanel({
        title: 'Average Connection Latency',
        targets: [
          {
            expr: 'rate(router_monitor_internet_connection_duration_seconds_sum{instance=~"$instance"}[$__rate_interval]) / rate(router_monitor_internet_connection_duration_seconds_count{instance=~"$instance"}[$__rate_interval])',
          },
        ],
        reduceCalc: 'mean',
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'green', value: null },
            { color: '#EAB839', value: 0.1 },
            { color: 'red', value: 0.2 },
          ],
        },
        defaultUnit: Unit.SECONDS,
      }),
      NewStatPanel({
        title: 'Max Connection Latency',
        targets: [{ expr: 'histogram_quantile(0.99, sum by (le) (rate(router_monitor_internet_connection_duration_seconds_bucket{instance=~"$instance"}[$__rate_interval])))' }],
        defaultUnit: Unit.SECONDS,
        reduceCalc: 'max',
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'green', value: null },
            { color: '#EAB839', value: 0.5 },
            { color: 'red', value: 1 },
          ],
        },
      }),
      NewStatPanel({
        title: 'DHCP Leases',
        description: 'Number of DHCP leases handed out',
        targets: [{ expr: 'router_monitor_dnsmasq_leases{instance=~"$instance"}' }],
        defaultUnit: Unit.SHORT,
      }),
      NewBarGaugePanel({
        title: 'Bandwidth Usage',
        targets: [
          { expr: 'sum by(src) (increase(router_monitor_bytes_total{dst=~"$localips",src=~"internet",instance=~"$instance"}[$__range]))', legendFormat: 'Download' },
          { expr: 'sum by(dst) (increase(router_monitor_bytes_total{src=~"$localips",dst=~"internet",instance=~"$instance"}[$__range]))', legendFormat: 'Upload' },
        ],
        defaultUnit: Unit.BYTES_SI,
        overrides: [
          {
            matcher: { id: 'byName', options: 'Upload' },
            properties: [{ id: 'color', value: { mode: 'fixed', fixedColor: 'blue' } }],
          },
          {
            matcher: { id: 'byName', options: 'Download' },
            properties: [{ id: 'color', value: { mode: 'fixed', fixedColor: 'green' } }],
          },
        ],
        options: { orientation: VizOrientation.Horizontal },
      }),
    ]),
  ]),
  NewPanelRow({ datasource, height: 6 }, [
    NewTimeSeriesPanel({
      title: 'Connection Latency',
      targets: [
        {
          expr: 'rate(router_monitor_internet_connection_duration_seconds_sum{instance=~"$instance"}[$__rate_interval])/\nrate(router_monitor_internet_connection_duration_seconds_count{instance=~"$instance"}[$__rate_interval])',
          legendFormat: 'average',
        },
        {
          expr: '1 - router_monitor_internet_connection_is_up{instance=~"$instance"}',
          legendFormat: 'down',
        },
        // {
        //   expr: 'histogram_quantile(0.99, sum by (le) (rate(router_monitor_internet_connection_duration_seconds_bucket{instance=~"$instance"}[$__rate_interval])))',
        //   legendFormat: '99p',
        // },
        {
          expr: 'histogram_quantile(0.95, sum by (le) (rate(router_monitor_internet_connection_duration_seconds_bucket{instance=~"$instance"}[$__rate_interval])))',
          legendFormat: '95p',
        },
        {
          expr: 'histogram_quantile(0.50, sum by (le) (rate(router_monitor_internet_connection_duration_seconds_bucket{instance=~"$instance"}[$__rate_interval])))',
          legendFormat: '50p',
        },
      ],
      options: {
        legend: { calcs: [], displayMode: LegendDisplayMode.List },
      },
      defaultUnit: Unit.SECONDS,
      overrides: [
        {
          matcher: { id: 'byName', options: 'down' },
          properties: [
            { id: 'color', value: { mode: 'fixed', fixedColor: 'red' } },
            { id: 'custom.drawStyle', value: 'bars' },
            { id: 'custom.fillOpacity', value: 100 },
            { id: 'custom.lineWidth', value: 0 },
            { id: 'max', value: 1 },
            { id: 'unit', value: 'short' },
          ],
        },
      ],
    }),
  ]),
  NewPanelRow({ datasource, height: 12 }, [
    NewTablePanel({
      title: 'DHCP Leases',
      targets: [{ expr: 'max(router_monitor_dnsmasq_lease_info{instance=~"$instance"}) by (devicename, ip, mac) * 1000', format: 'table' }],
      options: { cellHeight: TableCellHeight.Sm },
      overrides: [
        {
          matcher: { id: 'byName', options: 'Expires At' },
          properties: [{ id: 'unit', value: 'dateTimeAsLocalNoDateIfToday' }],
        },
        {
          matcher: { id: 'byName', options: 'Expires' },
          properties: [{ id: 'unit', value: 'dateTimeFromNow' }],
        },
      ],
      transformations: [
        {
          id: 'groupBy',
          options: {
            fields: {
              Time: { aggregations: [], operation: null },
              devicename: { aggregations: [], operation: 'groupby' },
              ip: { aggregations: [], operation: 'groupby' },
              mac: { aggregations: [], operation: 'groupby' },
              Value: { aggregations: ['lastNotNull'], operation: 'aggregate' },
            },
          },
        },
        {
          id: 'organize',
          options: {
            indexByName: { devicename: 0, mac: 1, ip: 2, 'Value (lastNotNull)': 3 },
            renameByName: {
              devicename: 'Device Name',
              mac: 'Mac Address',
              ip: 'IP Address',
              'Value (lastNotNull)': 'Expires At',
            },
          },
        },
        {
          id: 'calculateField',
          options: {
            mode: 'binary',
            reduce: { reducer: 'lastNotNull', include: ['Expires At'] },
            binary: { left: 'Expires At', reducer: 'sum', right: '0' },
            alias: 'Expires',
          },
        },
      ],
    }),
  ]),
  NewPanelGroup({ title: 'Network Traffic' }, networkTrafficPanels),
]

const dashboard: Dashboard = {
  ...defaultDashboard,
  description: 'Dashboard for Router Monitor',
  graphTooltip: DashboardCursorSync.Crosshair,
  style: 'dark',
  tags: ['router-monitor'],
  time: {
    from: 'now-6h',
    to: 'now',
  },
  title: 'Router Monitor',
  uid: 'router-monitor',
  version: 1,
  panels: autoLayout(panels),
  templating: {
    list: [
      NewPrometheusDatasourceVariable({ name: 'DS_PROMETHEUS', label: 'Prometheus' }),
      NewQueryVariable({ datasource, name: 'localips', label: 'Local IPs', query: 'label_values(router_monitor_packets_total, dst)', multi: true, includeAll: true }),
      NewQueryVariable({ datasource, name: 'instance', label: 'Instance', query: 'label_values(router_monitor_internet_connection_is_up, instance)' }),
    ],
  },
}

writeDashboardAndPostToGrafana({
  grafanaURL: process.env.GRAFANA_URL,
  dashboard,
  filename: 'router-monitor-dashboard.json',
})
