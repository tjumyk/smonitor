app = angular.module 'app', ['ngRoute']

app.config ['$routeProvider', '$locationProvider', ($routeProvider, $locationProvider)->
  $locationProvider.html5Mode(false)
  $routeProvider
    .when '/',
      templateUrl: 'static/ui/home.html'
      controller: 'HomeController'
    .when '/hosts/:hid',
      templateUrl: 'static/ui/host.html'
      controller: 'HostController'
    .otherwise
      templateUrl: 'static/ui/404.html'
]

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

app.controller('RootController', ['$scope', '$http', '$timeout', ($scope, $http, $timeout)->
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
    if info.swap
      info.swap.total_h = human_size(info.swap.total)
    if info.disk.partitions
      for part in info.disk.partitions
        part.total_h = human_size(part.total)
    boot_time_moment = moment.unix(info.boot_time)
    info.boot_time_h = boot_time_moment.format('lll')
    info.up_time = boot_time_moment.toNow(true)
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
    status.cpu.percent_h =status.cpu.percent + '%'
    status.memory.percent_h = status.memory.percent + '%'
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

app.controller 'HomeController', ['$scope', '$http', '$timeout', ($scope, $http, $timeout)->

]

app.controller 'HostController', ['$scope', '$http', '$timeout', '$routeParams', ($scope, $http, $timeout, $routeParams)->
  host_id = $routeParams['hid']

  process_full_status_message = (status)->
    if status.error
      return status
    status.memory.available_h = human_size(status.memory.available)
    status.memory.used_h = human_size(status.memory.used)
    status.memory.buffers_h = human_size(status.memory.buffers)
    status.memory.cached_h = human_size(status.memory.cached)
    status.memory.free_h = human_size(status.memory.free)
    if status.swap
      status.swap.free_h = human_size(status.swap.free)
      status.swap.percent_h = status.swap.percent + '%'
    for mount, part of status.disk.partitions
      part.free_h = human_size(part.free)
      part.used_h = human_size(part.used)
      part.percent_level = percent_level(part.percent)
    for user in status.users
      user.started_h = moment.unix(user.started).toNow()
    return status

  $scope.$on '$routeChangeStart', ->
    if $scope.socket
      $scope.socket.emit('disable_full_status', host_id)
    if $scope.host
      $scope.host.full_status = undefined

  $scope.$watch 'config', (config)->
    return if !config
    for host_group in $scope.config.host_groups
      for host in host_group.hosts
        if host.name == host_id
          $scope.host = host
          $scope.host_group = host_group
          break
      if $scope.host
        break

  $scope.$watch 'socket', (socket)->
    return if !socket
    socket.emit('enable_full_status', host_id)
    socket.on 'full_status', (full_status)->
      $timeout ->
        $scope.host.full_status = process_full_status_message(full_status)
    socket.on 'update_result', (result)->
      $timeout ->
        $scope.host.update_result = result
        $scope.host.updating = false
      if result.success
        $timeout ->
          $scope.host.update_result = undefined
        , 5000

  $scope.update = ->
    if $scope.host
      $scope.host.update_result = undefined
      $scope.host.updating = true
      $scope.socket.emit('update', $scope.host.name)
]
