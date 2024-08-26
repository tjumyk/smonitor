app = angular.module 'app', ['ngRoute']

app.config ['$routeProvider', '$locationProvider', ($routeProvider, $locationProvider)->
  $locationProvider.html5Mode(false)
  $routeProvider
    .when '/',
      templateUrl: 'static/ui/home.html?t=1806201'
      controller: 'HomeController'
    .when '/hosts/:hid',
      templateUrl: 'static/ui/host.html?t=1805171'
      controller: 'HostController'
    .otherwise
      templateUrl: 'static/ui/404.html'
]

app.directive 'appFooter', ->
  restrict: 'A'
  templateUrl: 'static/ui/footer.html?t=1805171'

parse_error_response = (response)->
  if !!response.data and typeof(response.data) == 'object'
    return response.data
  else if response.status == -1
    return {msg: "Connection Aborted!"}
  else
    return {msg: '[' + response.status + '] ' + response.statusText, detail: response.data}

human_size = (size)->
  if size == undefined or size == null
    return 'N/A'
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
  if percent == undefined or percent == null
    return 'N/A'
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
    if info.npu
      for npu in info.npu.devices
        npu.memory.total_h = human_size(npu.memory.total)
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
    if status.npu
      for npu in status.npu.devices
        npu.memory.free_h = human_size(npu.memory.free)
        npu.memory.used_h = human_size(npu.memory.used)
    return status

  process_proccess_info = (info)->
    for key, time of info.cpu_times
      info.cpu_times[key+'_h'] = format_cpu_time(time)
    if info.cmdline and info.cmdline.length > 0
      info.cmdline_h = info.cmdline.join(' ').trim()
    else
      info.cmdline_h = "[#{info.name}]"
    info.memory_info.rss_h = human_size(info.memory_info.rss)
    info.memory_info.vms_h = human_size(info.memory_info.vms)
    if info.memory_info.shared != undefined
      info.memory_info.shared_h = human_size(info.memory_info.shared)
    if info.gpu_memory != undefined
      info.gpu_memory_h = human_size(info.gpu_memory)
    if info.npu_memory != undefined
      info.npu_memory_h = human_size(info.npu_memory)

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

  $scope.gpu_memory_idle_threshold = 128 * 1024

  $scope.server_update = ->
    $scope.server_updating = true
    $http.get('api/check_update').then (response)->
      labels = response.data
      if labels.runtime_label == labels.latest_label
        $scope.server_updating = false
        alert('Server already up-to-date.')
      else
        if !confirm("New version available (#{labels.latest_label}). Do you want to update the server right now?")
          $scope.server_updating = false
          return
        $http.get('api/self_update').then (response)->
          $scope.server_updating = false
          alert('Server updated. It may take a few seconds to be ready. Click OK to reload this page.')
          window.location.reload()
        , (response)->
          $scope.server_updating = false
          if response.status == 401 and response.data.redirect_url # oauth redirect
            window.location.href = response.data.redirect_url
          console.error(response)
          if response.data.error
            alert(response.data.error)
    , (response)->
      $scope.server_updating = false
      if response.status == 401 and response.data.redirect_url # oauth redirect
        window.location.href = response.data.redirect_url
        return
      if response.data.error
        alert(response.data.error)

  $scope.server_restart = ->
    return if !confirm('Do you really want to restart the server?')
    $scope.server_restarting = true
    $http.get('api/self_restart').then (response)->
      $scope.server_restarting = false
      alert('A restart has been requested. It may take a few seconds to finish. Click OK to reload this page.')
      window.location.reload()
    , (response)->
      $scope.server_restarting = false
      if response.status == 401 and response.data.redirect_url # oauth redirect
        window.location.href = response.data.redirect_url
        return
      console.error(response)
      if response.data.error
        alert(response.data.error)

  init = (raw_config)->
    config = angular.copy(raw_config)
    config.site_title = config.site_name + ' \u00B7 System Monitor'

    $scope.loading_websocket = true
    socket = io({
      path: window.location.pathname + 'socket.io'
      reconnectionAttempts: 10
    })
    socket.on 'connect', ->
      $timeout ->
        $scope.loading_websocket = false
        $scope.init_success = true
    socket.on 'connect_error', ->
      $timeout ->
        $scope.loading_websocket = false
        $scope.init_error =
          msg: 'WebSocket: connection error'
    socket.on 'connect_timeout', ->
      $timeout ->
        $scope.loading_websocket = false
        $scope.init_error =
          msg: 'WebSocket: connection timeout'
    socket.on 'pong', (latency)->
      $timeout ->
        $scope.ping = latency
    socket.on 'reconnect', ->
      $('.reconnect.dimmer').dimmer('hide')
    socket.on 'reconnect_attempt', ->
      $('.reconnect.dimmer').dimmer({
        'closable': false
      }).dimmer('set page dimmer', true).dimmer('show')
      $http.get('api/config').then (response)->
        if not angular.equals(raw_config, response.data)
          window.location.reload()
      , (response)->
        if response.data
          if response.status == 401 and response.data.redirect_url # oauth redirect
            window.location.href = response.data.redirect_url
            return
          if response.data.error
            alert(response.data.error)
    socket.on 'reconnect_failed', ->
      $scope.reconnect_failed = true
    socket.on 'clients', (clients)->
      $scope.clients = clients
      total = 0
      for id, client of clients
        ua_str = client.user_agent
        if ua_str
          ua = new UAParser(ua_str)
          client.browser = ua.getBrowser()
          client.device = ua.getDevice()
          client.engine = ua.getEngine()
          client.os = ua.getOS()
          client.cpu = ua.getCPU()
        ++total
      $scope.clients_total = total

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

    if window.activityDetector
      detector = window.activityDetector(
        timeToIdle:  5 * 60 * 1000
      )
      detector.on 'idle', ->
        if socket.connected
          socket.disconnect()
      detector.on 'active', ->
        if socket.disconnected
          socket.connect()


  $scope.init_success = undefined
  $scope.init_error = undefined
  $scope.loading_config = true
  $http.get('api/config').then (response)->
    init(response.data)
  , (response)->
    if response.status == 401 and response.data.redirect_url # oauth redirect
      window.location.href = response.data.redirect_url
      return
    $scope.init_error = parse_error_response(response)
  .finally ->
    $scope.loading_config = false
])

app.controller 'HomeController', ['$scope', '$http', '$timeout', ($scope, $http, $timeout)->
  $timeout ->
    $('.init-box').addClass('active')
  , 100
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
    $timeout ->
      $('.host-switch').dropdown()
    socket.emit('enable_full_status', host_id)
    socket.on('reconnect', re_enable_full_status)

  $scope.update = ->
    if $scope.host
      $scope.host.update_result = undefined
      $scope.host.updating = true
      $scope.socket.emit('update', $scope.host.name)
]
