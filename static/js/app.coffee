app = angular.module 'app', ['ngRoute']

app.config ['$routeProvider', '$locationProvider', ($routeProvider, $locationProvider)->
  $locationProvider.html5Mode(false)
  $routeProvider
    .when '/',
      templateUrl: 'static/ui/home.html?t=1804191'
      controller: 'HomeController'
    .when '/hosts/:hid',
      templateUrl: 'static/ui/host.html?t=1804261'
      controller: 'HostController'
    .otherwise
      templateUrl: 'static/ui/404.html'
]

app.directive 'appFooter', ->
  restrict: 'A'
  templateUrl: 'static/ui/footer.html'

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

app.controller('RootController', ['$scope', '$http', '$timeout', '$interval', ($scope, $http, $timeout, $interval)->
  process_info_message = (info)->
    if info.error
      return info
    info.memory.total_h = human_size(info.memory.total)
    if info.disk.system
      info.disk.system.total_h = human_size(info.disk.system.total)
    else
      info.disk.system =
        total_h: 'N/A'
    if info.disk.boot
      info.disk.boot.total_h = human_size(info.disk.boot.total)
    else
      info.disk.boot =
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
    info.boot_time_moment = moment.unix(info.boot_time)
    info.boot_time_h = info.boot_time_moment.format('lll')
    info.up_time = info.boot_time_moment.toNow(true)
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
    if status.disk.boot
      status.disk.boot.percent_h = status.disk.boot.percent + '%'
      status.disk.boot.percent_level = percent_level(status.disk.boot.percent)
    else
      status.disk.boot =
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

  process_full_status_message = (status)->
    if status.error
      return status
    status.memory.available_h = human_size(status.memory.available)
    status.memory.used_h = human_size(status.memory.used)
    status.memory.free_h = human_size(status.memory.free)
    if status.memory.buffers != undefined
      status.memory.buffers_h = human_size(status.memory.buffers)
      status.memory.buffers_offset = status.memory.used_percent
    if status.memory.cached != undefined
      status.memory.cached_h = human_size(status.memory.cached)
      status.memory.cached_offset = status.memory.used_percent
      if status.memory.buffers != undefined
        status.memory.cached_offset += status.memory.buffers_percent
    if status.swap
      status.swap.free_h = human_size(status.swap.free)
      status.swap.percent_h = status.swap.percent + '%'
    for name, part of status.disk.partitions
      part.free_h = human_size(part.free)
      part.used_h = human_size(part.used)
      part.percent_level = percent_level(part.percent)
    for user in status.users
      user.started_h = moment.unix(user.started).toNow()
    for proc in status.cpu.top_processes
      process_proccess_info(proc)
    for proc in status.memory.top_processes
      process_proccess_info(proc)
    if status.gpu
      for gpu in status.gpu.devices
        gpu.memory.free_h = human_size(gpu.memory.free)
        gpu.memory.used_h = human_size(gpu.memory.used)
        if gpu.power
          gpu.power.usage_h = Math.round(gpu.power.usage / 100) / 10 + 'W'
          gpu.power.limit_h = Math.round(gpu.power.limit / 100) / 10 + 'W'
          gpu.power.percent = Math.round(gpu.power.usage/gpu.power.limit*100)
        if gpu.performance != undefined
          gpu.performance_percent = gpu.performance * (-100/15) + 100
        for proc in gpu.process_list
          process_proccess_info(proc)
    return status

  process_proccess_info = (info)->
    for key, time of info.cpu_times
      info.cpu_times[key+'_h'] = format_cpu_time(time)
    if info.cmdline.length > 0
      info.cmdline_h = info.cmdline.join(' ').trim()
    else
      info.cmdline_h = "[#{info.name}]"
    info.memory_info.rss_h = human_size(info.memory_info.rss)
    info.memory_info.vms_h = human_size(info.memory_info.vms)
    info.memory_info.shared_h = human_size(info.memory_info.shared)
    if info.gpu_memory != undefined
      info.gpu_memory_h = human_size(info.gpu_memory)

  format_cpu_time = (time)->
    hours = Math.floor(time / 3600)
    time -= hours * 3600
    minutes = Math.floor(time / 60)
    time -= minutes * 60
    output = ''
    if hours > 0
      output += hours+'h'
    if minutes < 10
      output += '0'
    output += minutes + ':'
    if time < 10
      output += '0'
    output += time.toFixed(2)
    return output


  handle_update_result_message = (host, message)->
    host.update_result = message
    host.updating = false
    if message.success
      $timeout ->
        host.update_result = undefined
      , 5000

  update_uptime = ->
    for host_group in $scope.config.host_groups
      for host in host_group.hosts
        if host.info and host.info.boot_time_moment
          host.info.up_time = host.info.boot_time_moment.toNow(true)

  $scope.server_update = ->
    $scope.server_updating = true
    $http.get('api/self_update').then (response)->
      $scope.server_updating = false
      if response.data.already_latest
        alert('Server already up-to-date.')
      else
        alert('Server updated. Click OK to reload this page.')
        window.location.reload()
    , (response)->
      $scope.server_updating = false
      console.error(response)
      if response.data.error
        alert(response.data.error)

  $http.get('api/config').then (response)->
    raw_config = response.data
    config = angular.copy(raw_config)
    config.site_title = config.site_name + ' \u00B7 System Monitor'

    socket = io({
      path: window.location.pathname + 'socket.io'
    })
    socket.on 'pong', (latency)->
      $timeout ->
        $scope.ping = latency
    socket.on 'reconnect', ->
      $('.reconnect.dimmer').dimmer('hide')
      $http.get('api/config').then (response)->
        if not angular.equals(raw_config, response.data)
          window.location.reload()
    socket.on 'reconnect_attempt', ->
      $('.reconnect.dimmer').dimmer({
        'closable': false
      }).dimmer('set page dimmer', true).dimmer('show')

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
      socket.on 'full_status', (message)->
        $timeout ->
          for name, full_status_message of message
            host_map[name].full_status = process_full_status_message(full_status_message)
      socket.on 'update_result', (message)->
        $timeout ->
          for name, result_message of message
            handle_update_result_message(host_map[name], result_message)
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
      socket.on 'full_status', (message)->
        $timeout ->
          local_host.full_status = process_full_status_message(message)

    $scope.config = config
    $scope.socket = socket

    handle = $interval(update_uptime, 30 * 1000)
    $scope.$on '$destroy', ->
      $interval.cancel(handle)
])

app.controller 'HomeController', ['$scope', '$http', '$timeout', ($scope, $http, $timeout)->
]

app.controller 'HostController', ['$scope', '$http', '$timeout', '$routeParams', '$location', ($scope, $http, $timeout, $routeParams, $location)->
  host_id = $routeParams['hid']

  re_enable_full_status = ->
    $scope.socket.emit('enable_full_status', host_id)

  $scope.$on '$destroy', ->
    if $scope.socket and $scope.host
      $scope.socket.off('reconnect', re_enable_full_status)
      $scope.socket.emit('disable_full_status', host_id)
    if $scope.host
      $scope.host.full_status = undefined

  $scope.$watch 'socket', (socket)->
    return if !socket
    for host_group in $scope.config.host_groups
      for host in host_group.hosts
        if host.name == host_id
          $scope.host = host
          $scope.host_group = host_group
          break
      if $scope.host
        break
    if !$scope.host
      $location.path('/404').replace()
      return
    socket.emit('enable_full_status', host_id)
    socket.on('reconnect', re_enable_full_status)

  $scope.update = ->
    if $scope.host
      $scope.host.update_result = undefined
      $scope.host.updating = true
      $scope.socket.emit('update', $scope.host.name)
]
