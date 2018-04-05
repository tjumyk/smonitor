app = angular.module('app', [])

app.controller('MainController', ['$scope', '$http', '$timeout', ($scope, $http, $timeout)->
  human_size = (size)->
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_pos = 0
    while size >= 1000 and unit_pos < units.length - 1
      size /= 1024.0
      unit_pos += 1
    if size < 1
      size = Math.round(size * 100) / 100
    else
      size = Math.round(size * 10) / 10
    return "#{size}#{units[unit_pos]}"

  percent_level = (percent)->
    if percent < 80
      return ''
    if percent < 90
      return 'warning'
    return 'danger'

  process_status_message = (status)->
    if status.error
      console.error(status.error)
      return status

    status.memory.total_h = human_size(status.memory.total)
    if status.disk.system
      status.disk.system.total_h = human_size(status.disk.system.total)
      status.disk.system.percent_h = status.disk.system.percent + '%'
    else
      status.disk.system =
        total_h: 'N/A'
        percent_h: 'N/A'
    if status.disk.others
      status.disk.others.total_h = human_size(status.disk.others.total)
      status.disk.others.percent_h = status.disk.others.percent + '%'
    else
      status.disk.others =
        total_h: 'N/A'
        percent_h: 'N/A'

    status.up_time = moment.unix(status.boot_time).toNow(true)

    status.cpu.percent_level = percent_level(status.cpu.percent)
    status.memory.percent_level = percent_level(status.memory.percent)
    if status.disk.system.total
      status.disk.system.percent_level = percent_level(status.disk.system.percent)
    if status.disk.others.total
      status.disk.others.percent_level = percent_level(status.disk.others.percent)

    if status.gpu
      for gpu in status.gpu.devices
        gpu.memory.total_h = human_size(gpu.memory.total)

    return status

  $http.get('api/basic').then (response)->
    $scope.config = config =response.data.config
    $scope.info = response.data.info

    config.site_title = config.site_name + ' \u00B7 System Monitor'
    $scope.socket = socket = io()

    if config.mode == 'app'
      host_map = {}
      for host_group in config.host_groups
        for host in host_group.hosts
          host_map[host.name] = host
      socket.on 'status', (message)->
        $timeout ->
          for name, status_message of message
            host_map[name].status = process_status_message(status_message)
    else
      local_host =
        name: 'local'
        address: 'localhost'
      local_host_group =
        name: 'Local Node'
        hosts: [local_host]
      config.host_groups = [local_host_group]

      socket.on 'status', (message)->
        $timeout ->
          local_host.status = process_status_message(message)
])
