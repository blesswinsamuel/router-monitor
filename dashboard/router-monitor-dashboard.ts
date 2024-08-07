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

const totalBytesByLocalIPQuery = (labels: string, ipLabel: string, queryType: string, queryFunc: string, extraFields: boolean = true) =>
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
* on(ip_addr) group_left(hw_addr, device, hostname) (${queryType === '$__range' ? 'keep_last_value' : ''}(
    sum by (ip_addr, hw_addr, device, hostname) (router_monitor_arp_devices{instance=~"$instance"})
  ) * 0 + 1)
` // hack: $__range is used only in pie chart, which is an instant query
    : '')

const totalBytesByLocalIPPieChartPanel = (uploadOrDownload: string, labels: string, ipLabel: string) =>
  NewPieChartPanel({
    title: `Total Bytes ${uploadOrDownload}ed - by local IP (pie chart)`,
    targets: [{ expr: totalBytesByLocalIPQuery(labels, ipLabel, '$__range', 'increase'), legendFormat: '{{ hostname }} ({{ ip_addr }})', type: 'instant' }],
    defaultUnit: Unit.BYTES_SI,
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
        targets: [{ expr: 'max(router_monitor_internet_connection_is_up{instance=~"$instance"})' }],
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
        targets: [{ expr: '(1 - avg_over_time(max(router_monitor_internet_connection_is_up{instance=~"$instance"})[$__range])) * $__range_s' }],
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'green', value: null },
            { color: 'red', value: 1 },
          ],
        },
        defaultUnit: Unit.SECONDS,
        interval: '1m',
        maxDataPoints: 1000,
      }),
      NewStatPanel({
        title: 'Average Connection Latency',
        targets: [
          {
            expr: 'avg(rate(router_monitor_internet_connection_duration_seconds_sum{instance=~"$instance"}[$__rate_interval]) / rate(router_monitor_internet_connection_duration_seconds_count{instance=~"$instance"}[$__rate_interval]))',
          },
        ],
        reduceCalc: 'lastNotNull',
        thresholds: {
          mode: ThresholdsMode.Absolute,
          steps: [
            { color: 'green', value: null },
            { color: '#EAB839', value: 0.1 },
            { color: 'red', value: 0.3 },
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
        targets: [{ expr: 'count(last_over_time((router_monitor_arp_devices{instance=~"$instance"} == 2)[$__range]))' }],
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
          expr: 'rate(router_monitor_internet_connection_duration_seconds_sum{instance=~"$instance"}[$__rate_interval]) / rate(router_monitor_internet_connection_duration_seconds_count{instance=~"$instance"}[$__rate_interval])',
          legendFormat: '{{ addr }} average',
        },
        {
          expr: '1 - max(router_monitor_internet_connection_is_up{instance=~"$instance"})',
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
    NewTimeSeriesPanel({
      title: 'Connection down',
      targets: [
        {
          expr: '1 - router_monitor_internet_connection_is_up{instance=~"$instance"}',
          legendFormat: '{{ addr }} down',
        },
      ],
      type: 'bar',
      options: {
        legend: { calcs: [], displayMode: LegendDisplayMode.List },
      },
      defaultUnit: Unit.SECONDS,
      // overrides: [
      //   {
      //     matcher: { id: 'byName', options: 'down' },
      //     properties: [
      //       { id: 'color', value: { mode: 'fixed', fixedColor: 'red' } },
      //       { id: 'custom.drawStyle', value: 'bars' },
      //       { id: 'custom.fillOpacity', value: 100 },
      //       { id: 'custom.lineWidth', value: 0 },
      //       { id: 'max', value: 1 },
      //       { id: 'unit', value: 'short' },
      //     ],
      //   },
      // ],
    }),
  ]),
  NewPanelRow({ datasource, height: 12 }, [
    NewTablePanel({
      title: 'Connected Devices',
      targets: [
        {
          expr: 'sum by (ip_addr, hw_addr, hostname, device) (router_monitor_arp_devices{instance=~"$instance"})',
          // expr: 'sum by (ip_addr, hw_addr, device) (last_over_time(router_monitor_arp_devices{instance=~"$instance"}[$__range])) * on(ip_addr) group_left(hostname) max by (ip_addr, hostname) (last_over_time(router_monitor_hostnames{instance=~"$instance"}[$__range]))',
          format: 'table',
          type: 'instant',
          refId: 'DEVICE',
        },
        {
          expr: 'label_move(sum by (dst) (increase(router_monitor_bytes_total{dst=~"$localips",src=~"internet",instance=~"$instance"}[$__range]) > 0), "dst", "ip_addr")',
          format: 'table',
          type: 'instant',
          refId: 'INGRESS_BYTES',
        },
        {
          expr: 'label_move(sum by (dst) (increase(router_monitor_packets_total{dst=~"$localips",src=~"internet",instance=~"$instance"}[$__range]) > 0), "dst", "ip_addr")',
          format: 'table',
          type: 'instant',
          refId: 'INGRESS_PACKETS',
        },
        {
          expr: 'label_move(sum by (src) (increase(router_monitor_bytes_total{src=~"$localips",dst=~"internet",instance=~"$instance"}[$__range]) > 0), "src", "ip_addr")',
          format: 'table',
          type: 'instant',
          refId: 'EGRESS_BYTES',
        },
        {
          expr: 'label_move(sum by (src) (increase(router_monitor_packets_total{src=~"$localips",dst=~"internet",instance=~"$instance"}[$__range]) > 0), "src", "ip_addr")',
          format: 'table',
          type: 'instant',
          refId: 'EGRESS_PACKETS',
        },
      ],
      options: {
        cellHeight: TableCellHeight.Sm,
        sortBy: [{ displayName: 'Downloaded', desc: true }],
      },
      thresholds: { mode: ThresholdsMode.Absolute, steps: [{ color: 'green', value: null }] },
      overrides: [
        {
          matcher: { id: 'byName', options: 'Flags' },
          properties: [
            { id: 'mappings', value: [{ type: 'value', options: { '0': { text: 'INVALID', color: 'red', index: 0 }, '2': { text: 'VALID', color: 'green', index: 1 } } }] },
            { id: 'custom.cellOptions', value: { type: 'color-background' } },
            { id: 'custom.width', value: 75 },
          ],
        },
        {
          matcher: { id: 'byName', options: 'Downloaded' },
          properties: [
            { id: 'unit', value: Unit.BYTES_SI },
            { id: 'custom.cellOptions', value: { type: 'gauge', mode: 'basic', valueDisplayMode: 'text' } },
          ],
        },
        {
          matcher: { id: 'byName', options: 'DL Pkts' },
          properties: [
            { id: 'unit', value: Unit.SHORT },
            { id: 'custom.width', value: 100 },
          ],
        },
        {
          matcher: { id: 'byName', options: 'Uploaded' },
          properties: [
            { id: 'unit', value: Unit.BYTES_SI },
            { id: 'custom.cellOptions', value: { type: 'gauge', mode: 'basic', valueDisplayMode: 'text' } },
          ],
        },
        {
          matcher: { id: 'byName', options: 'UL Pkts' },
          properties: [
            { id: 'unit', value: Unit.SHORT },
            { id: 'custom.width', value: 100 },
          ],
        },
        { matcher: { id: 'byName', options: 'Hostname' }, properties: [{ id: 'custom.width', value: 240 }] },
        { matcher: { id: 'byName', options: 'IP Address' }, properties: [{ id: 'custom.width', value: 180 }] },
        { matcher: { id: 'byName', options: 'Mac Address' }, properties: [{ id: 'custom.width', value: 180 }] },
        { matcher: { id: 'byName', options: 'Interface' }, properties: [{ id: 'custom.width', value: 100 }] },
      ],
      transformations: [
        { id: 'joinByField', options: { byField: 'ip_addr', mode: 'outer' } },
        {
          id: 'organize',
          options: {
            excludeByName: tableExcludeByName(['Time']),
            indexByName: tableIndexByName(['hostname', 'ip_addr', 'hw_addr', 'device']),
            renameByName: {
              hostname: 'Hostname',
              device: 'Interface',
              hw_addr: 'Mac Address',
              ip_addr: 'IP Address',
              'Value #DEVICE': 'Flags',
              'Value #INGRESS_BYTES': 'Downloaded',
              'Value #EGRESS_BYTES': 'Uploaded',
              'Value #INGRESS_PACKETS': 'DL Pkts',
              'Value #EGRESS_PACKETS': 'UL Pkts',
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
