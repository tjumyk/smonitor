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

  process_info_message = (info)->
    if info.error
      return info
    info.memory.total_h = human_size(info.memory.total)
    if info.disk.system
      info.disk.system.total_h = human_size(info.disk.system.total)
    else
      info.disk.system =
        total_h: 'N/A'
    if info.disk.others
      info.disk.others.total_h = human_size(info.disk.others.total)
    else
      info.disk.others =
        total_h: 'N/A'
    info.up_time = moment.unix(info.boot_time).toNow(true)
    if info.gpu
      for gpu in info.gpu.devices
        gpu.memory.total_h = human_size(gpu.memory.total)
    return info

  process_status_message = (status)->
    if status.error
      return status
    if status.disk.system
      status.disk.system.percent_h = status.disk.system.percent + '%'
      status.disk.system.percent_level = percent_level(status.disk.system.percent)
    else
      status.disk.system =
        percent_h: 'N/A'
    if status.disk.others
      status.disk.others.percent_h = status.disk.others.percent + '%'
      status.disk.others.percent_level = percent_level(status.disk.others.percent)
    else
      status.disk.others =
        percent_h: 'N/A'
    status.cpu.percent_level = percent_level(status.cpu.percent)
    status.memory.percent_level = percent_level(status.memory.percent)
    return status

  $http.get('api/config').then (response)->
    $scope.config = config = response.data

    config.site_title = config.site_name + ' \u00B7 System Monitor'
    $scope.socket = socket = io({
      path: window.location.pathname + 'socket.io'
    })

    if config.mode == 'app'
      host_map = {}
      for host_group in config.host_groups
        for host in host_group.hosts
          host_map[host.name] = host
      socket.on 'info', (message)->
        $timeout ->
          for name, info_message of message
            host_map[name].info = process_info_message(info_message)
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
      socket.on 'info', (message)->
        $timeout ->
          local_host.info = process_info_message(message)
      socket.on 'status', (message)->
        $timeout ->
          local_host.status = process_status_message(message)
])
