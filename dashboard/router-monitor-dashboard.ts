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
  tableExcludeByName,
  tableIndexByName,
  writeDashboardAndPostToGrafana,
} from 'grafana-dashboard-helpers'

const datasource: DataSourceRef = {
  uid: '${DS_PROMETHEUS}',
}

const totalBytesByLocalIPQuery = (labels: string, ipLabel: string, queryType: string = '$__range', queryFunc: string = 'increase', extraFields: boolean = true) =>
  `
label_replace(
  sum by(${ipLabel}) (
    ${queryFunc}(
      router_monitor_bytes_total{${labels},instance=~"$instance"}[${queryType}]
    ) > 0
  ),
  "ip_addr", "$1", "${ipLabel}", "(.*)"
)` +
  (extraFields
    ? `
+ on(ip_addr) group_left(hw_addr, device, flags) router_monitor_arp_devices
+ on(ip_addr) group_left(hostname) router_monitor_hostnames
`
    : '')

const totalBytesByLocalIPPieChartPanel = (uploadOrDownload: string, labels: string, ipLabel: string) =>
  NewPieChartPanel({
    title: `Total Bytes ${uploadOrDownload}ed - by local IP (pie chart)`,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel), legendFormat: '{{ hostname }} ({{ ip_addr }})', type: 'instant' }],
    defaultUnit: Unit.BYTES_SI,
  })

const totalBytesByLocalIPBarGaugePanel = (uploadOrDownload: string, labels: string, ipLabel: string) =>
  NewBarGaugePanel({
    title: `Total Bytes ${uploadOrDownload}ed - by local IP (bar gauge)`,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel), legendFormat: '{{ hostname }} ({{ ip_addr }})', type: 'instant' }],
    defaultUnit: Unit.BYTES_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    options: { orientation: VizOrientation.Horizontal },
  })

const totalBytesTimeSeriesPanel = (title: string, labels: string, ipLabel: string, isInternetTotalGraph: boolean = false) =>
  NewTimeSeriesPanel({
    title: title,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel, '$__interval', 'increase', !isInternetTotalGraph), legendFormat: `{{ hostname }} ({{ ip_addr }})` }],
    defaultUnit: Unit.BYTES_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    type: 'bar',
    options: { legend: { calcs: ['sum'], placement: 'bottom' } },
  })

const dataRateTimeSeriesPanel = (title: string, labels: string, ipLabel: string, isInternetTotalGraph: boolean = false) =>
  NewTimeSeriesPanel({
    title,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel, '$__rate_interval', 'rate', !isInternetTotalGraph), legendFormat: `{{ hostname }} ({{ ip_addr }})` }],
    defaultUnit: Unit.BYTES_PER_SEC_SI,
    thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
    options: { legend: { calcs: ['mean', 'min', 'max'], placement: 'bottom' } },
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
    totalBytesTimeSeriesPanel('Total bytes downloaded', 'dst=~"$localips",src=~"internet"', 'src', true),
    totalBytesTimeSeriesPanel('Total bytes uploaded', 'src=~"$localips",dst=~"internet"', 'dst', true),
    dataRateTimeSeriesPanel('Download Data Rate', 'dst=~"$localips",src=~"internet"', 'src', true),
    dataRateTimeSeriesPanel('Upload Data Rate', 'src=~"$localips",dst=~"internet"', 'dst', true),
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
        title: 'No. of devices',
        description: 'Number of devices connected',
        targets: [{ expr: 'count(router_monitor_arp_devices{instance=~"$instance"})' }],
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
      title: 'Connected Devices',
      targets: [{ expr: 'label_del(router_monitor_arp_devices + on(ip_addr) group_left(hostname) router_monitor_hostnames, "job", "instance")', format: 'table', type: 'instant' }],
      options: { cellHeight: TableCellHeight.Sm },
      overrides: [
        {
          matcher: { id: 'byName', options: 'Flags' },
          properties: [
            {
              id: 'mappings',
              value: [
                {
                  type: 'value',
                  options: {
                    '0x0': { text: 'INVALID', color: 'red', index: 0 },
                    '0x2': { text: 'VALID', color: 'green', index: 1 },
                  },
                },
              ],
            },
            { id: 'custom.cellOptions', value: { type: 'color-background' } },
          ],
        },
      ],
      transformations: [
        {
          id: 'organize',
          options: {
            excludeByName: tableExcludeByName(['Value', 'Time']),
            indexByName: tableIndexByName(['flags', 'hostname', 'ip_addr', 'hw_addr', 'device']),
            renameByName: {
              hostname: 'Hostname',
              device: 'Interface',
              hw_addr: 'Mac Address',
              ip_addr: 'IP Address',
              flags: 'Flags',
            },
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
  tags: ['router-monitor'],
  time: {
    from: 'now-24h',
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
  dashboard,
  filename: 'router-monitor-dashboard.json',
})
