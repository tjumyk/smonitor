// Generated by CoffeeScript 1.12.7
(function() {
  var app, human_size, percent_level;

  app = angular.module('app', ['ngRoute']);

  app.config([
    '$routeProvider', '$locationProvider', function($routeProvider, $locationProvider) {
      $locationProvider.html5Mode(false);
      return $routeProvider.when('/', {
        templateUrl: 'static/ui/home.html?t=1804191',
        controller: 'HomeController'
      }).when('/hosts/:hid', {
        templateUrl: 'static/ui/host.html?t=1805171',
        controller: 'HostController'
      }).otherwise({
        templateUrl: 'static/ui/404.html'
      });
    }
  ]);

  app.directive('appFooter', function() {
    return {
      restrict: 'A',
      templateUrl: 'static/ui/footer.html?t=1805171'
    };
  });

  human_size = function(size) {
    var unit_pos, units;
    if (size === void 0 || size === null) {
      return 'N/A';
    }
    units = ['B', 'KB', 'MB', 'GB', 'TB'];
    unit_pos = 0;
    while (size >= 1000 && unit_pos < units.length - 1) {
      size /= 1024.0;
      unit_pos += 1;
    }
    if (size < 1) {
      size = Math.round(size * 100) / 100;
    } else {
      size = Math.round(size * 10) / 10;
    }
    return "" + size + units[unit_pos];
  };

  percent_level = function(percent) {
    if (percent === void 0 || percent === null) {
      return 'N/A';
    }
    if (percent < 80) {
      return '';
    }
    if (percent < 90) {
      return 'warning';
    }
    return 'danger';
  };

  app.controller('RootController', [
    '$scope', '$http', '$timeout', '$interval', function($scope, $http, $timeout, $interval) {
      var format_cpu_time, handle_update_result_message, process_full_status_message, process_info_message, process_proccess_info, process_status_message, update_uptime;
      process_info_message = function(info) {
        var gpu, i, j, len, len1, part, ref, ref1;
        if (info.error) {
          return info;
        }
        info.memory.total_h = human_size(info.memory.total);
        if (info.disk.system) {
          info.disk.system.total_h = human_size(info.disk.system.total);
        } else {
          info.disk.system = {
            total_h: 'N/A'
          };
        }
        if (info.disk.boot) {
          info.disk.boot.total_h = human_size(info.disk.boot.total);
        } else {
          info.disk.boot = {
            total_h: 'N/A'
          };
        }
        if (info.disk.others) {
          info.disk.others.total_h = human_size(info.disk.others.total);
        } else {
          info.disk.others = {
            total_h: 'N/A'
          };
        }
        if (info.swap) {
          info.swap.total_h = human_size(info.swap.total);
        }
        if (info.disk.partitions) {
          ref = info.disk.partitions;
          for (i = 0, len = ref.length; i < len; i++) {
            part = ref[i];
            part.total_h = human_size(part.total);
          }
        }
        info.boot_time_moment = moment.unix(info.boot_time);
        info.boot_time_h = info.boot_time_moment.format('lll');
        info.up_time = info.boot_time_moment.toNow(true);
        if (info.gpu) {
          ref1 = info.gpu.devices;
          for (j = 0, len1 = ref1.length; j < len1; j++) {
            gpu = ref1[j];
            gpu.memory.total_h = human_size(gpu.memory.total);
          }
        }
        return info;
      };
      process_status_message = function(status) {
        if (status.error) {
          return status;
        }
        if (status.disk.system) {
          status.disk.system.percent_h = status.disk.system.percent + '%';
          status.disk.system.percent_level = percent_level(status.disk.system.percent);
        } else {
          status.disk.system = {
            percent_h: 'N/A'
          };
        }
        if (status.disk.boot) {
          status.disk.boot.percent_h = status.disk.boot.percent + '%';
          status.disk.boot.percent_level = percent_level(status.disk.boot.percent);
        } else {
          status.disk.boot = {
            percent_h: 'N/A'
          };
        }
        if (status.disk.others) {
          status.disk.others.percent_h = status.disk.others.percent + '%';
          status.disk.others.percent_level = percent_level(status.disk.others.percent);
        } else {
          status.disk.others = {
            percent_h: 'N/A'
          };
        }
        status.cpu.percent_h = status.cpu.percent + '%';
        status.memory.percent_h = status.memory.percent + '%';
        status.cpu.percent_level = percent_level(status.cpu.percent);
        status.memory.percent_level = percent_level(status.memory.percent);
        return status;
      };
      process_full_status_message = function(status) {
        var gpu, i, j, k, l, len, len1, len2, len3, len4, m, name, part, proc, ref, ref1, ref2, ref3, ref4, ref5, user;
        if (status.error) {
          return status;
        }
        status.memory.available_h = human_size(status.memory.available);
        status.memory.used_h = human_size(status.memory.used);
        status.memory.free_h = human_size(status.memory.free);
        if (status.memory.buffers !== void 0) {
          status.memory.buffers_h = human_size(status.memory.buffers);
          status.memory.buffers_offset = status.memory.used_percent;
        }
        if (status.memory.cached !== void 0) {
          status.memory.cached_h = human_size(status.memory.cached);
          status.memory.cached_offset = status.memory.used_percent;
          if (status.memory.buffers !== void 0) {
            status.memory.cached_offset += status.memory.buffers_percent;
          }
        }
        if (status.swap) {
          status.swap.free_h = human_size(status.swap.free);
          status.swap.percent_h = status.swap.percent + '%';
        }
        ref = status.disk.partitions;
        for (name in ref) {
          part = ref[name];
          part.free_h = human_size(part.free);
          part.used_h = human_size(part.used);
          part.percent_level = percent_level(part.percent);
        }
        ref1 = status.users;
        for (i = 0, len = ref1.length; i < len; i++) {
          user = ref1[i];
          user.started_h = moment.unix(user.started).toNow();
        }
        ref2 = status.cpu.top_processes;
        for (j = 0, len1 = ref2.length; j < len1; j++) {
          proc = ref2[j];
          process_proccess_info(proc);
        }
        ref3 = status.memory.top_processes;
        for (k = 0, len2 = ref3.length; k < len2; k++) {
          proc = ref3[k];
          process_proccess_info(proc);
        }
        if (status.gpu) {
          ref4 = status.gpu.devices;
          for (l = 0, len3 = ref4.length; l < len3; l++) {
            gpu = ref4[l];
            gpu.memory.free_h = human_size(gpu.memory.free);
            gpu.memory.used_h = human_size(gpu.memory.used);
            if (gpu.power) {
              gpu.power.usage_h = Math.round(gpu.power.usage / 100) / 10 + 'W';
              gpu.power.limit_h = Math.round(gpu.power.limit / 100) / 10 + 'W';
              gpu.power.percent = Math.round(gpu.power.usage / gpu.power.limit * 100);
            }
            if (gpu.performance !== void 0) {
              gpu.performance_percent = gpu.performance * (-100 / 15) + 100;
            }
            ref5 = gpu.process_list;
            for (m = 0, len4 = ref5.length; m < len4; m++) {
              proc = ref5[m];
              process_proccess_info(proc);
            }
          }
        }
        return status;
      };
      process_proccess_info = function(info) {
        var key, ref, time;
        ref = info.cpu_times;
        for (key in ref) {
          time = ref[key];
          info.cpu_times[key + '_h'] = format_cpu_time(time);
        }
        if (info.cmdline && info.cmdline.length > 0) {
          info.cmdline_h = info.cmdline.join(' ').trim();
        } else {
          info.cmdline_h = "[" + info.name + "]";
        }
        info.memory_info.rss_h = human_size(info.memory_info.rss);
        info.memory_info.vms_h = human_size(info.memory_info.vms);
        if (info.memory_info.shared !== void 0) {
          info.memory_info.shared_h = human_size(info.memory_info.shared);
        }
        if (info.gpu_memory !== void 0) {
          return info.gpu_memory_h = human_size(info.gpu_memory);
        }
      };
      format_cpu_time = function(time) {
        var hours, minutes, output;
        hours = Math.floor(time / 3600);
        time -= hours * 3600;
        minutes = Math.floor(time / 60);
        time -= minutes * 60;
        output = '';
        if (hours > 0) {
          output += hours + 'h';
        }
        if (minutes < 10) {
          output += '0';
        }
        output += minutes + ':';
        if (time < 10) {
          output += '0';
        }
        output += time.toFixed(2);
        return output;
      };
      handle_update_result_message = function(host, message) {
        host.update_result = message;
        host.updating = false;
        if (message.success) {
          return $timeout(function() {
            return host.update_result = void 0;
          }, 5000);
        }
      };
      update_uptime = function() {
        var host, host_group, i, len, ref, results;
        ref = $scope.config.host_groups;
        results = [];
        for (i = 0, len = ref.length; i < len; i++) {
          host_group = ref[i];
          results.push((function() {
            var j, len1, ref1, results1;
            ref1 = host_group.hosts;
            results1 = [];
            for (j = 0, len1 = ref1.length; j < len1; j++) {
              host = ref1[j];
              if (host.info && host.info.boot_time_moment) {
                results1.push(host.info.up_time = host.info.boot_time_moment.toNow(true));
              } else {
                results1.push(void 0);
              }
            }
            return results1;
          })());
        }
        return results;
      };
      $scope.gpu_memory_idle_threshold = 128 * 1024;
      $scope.server_update = function() {
        $scope.server_updating = true;
        return $http.get('api/check_update').then(function(response) {
          var labels;
          labels = response.data;
          if (labels.runtime_label === labels.latest_label) {
            $scope.server_updating = false;
            return alert('Server already up-to-date.');
          } else {
            if (!confirm("New version available (" + labels.latest_label + "). Do you want to update the server right now?")) {
              $scope.server_updating = false;
              return;
            }
            return $http.get('api/self_update').then(function(response) {
              $scope.server_updating = false;
              alert('Server updated. It may take a few seconds to be ready. Click OK to reload this page.');
              return window.location.reload();
            }, function(response) {
              $scope.server_updating = false;
              console.error(response);
              if (response.data.error) {
                return alert(response.data.error);
              }
            });
          }
        }, function(response) {
          $scope.server_updating = false;
          console.error(response);
          if (response.data.error) {
            return alert(response.data.error);
          }
        });
      };
      $scope.server_restart = function() {
        if (!confirm('Do you really want to restart the server?')) {
          return;
        }
        $scope.server_restarting = true;
        return $http.get('api/self_restart').then(function(response) {
          $scope.server_restarting = false;
          alert('A restart has been requested. It may take a few seconds to finish. Click OK to reload this page.');
          return window.location.reload();
        }, function(response) {
          $scope.server_restarting = false;
          console.error(response);
          if (response.data.error) {
            return alert(response.data.error);
          }
        });
      };
      return $http.get('api/config').then(function(response) {
        var config, handle, host, host_group, host_map, i, j, len, len1, local_host, local_host_group, raw_config, ref, ref1, socket;
        raw_config = response.data;
        config = angular.copy(raw_config);
        config.site_title = config.site_name + ' \u00B7 System Monitor';
        socket = io({
          path: window.location.pathname + 'socket.io'
        });
        socket.on('pong', function(latency) {
          return $timeout(function() {
            return $scope.ping = latency;
          });
        });
        socket.on('reconnect', function() {
          $('.reconnect.dimmer').dimmer('hide');
          return $http.get('api/config').then(function(response) {
            if (!angular.equals(raw_config, response.data)) {
              return window.location.reload();
            }
          });
        });
        socket.on('reconnect_attempt', function() {
          return $('.reconnect.dimmer').dimmer({
            'closable': false
          }).dimmer('set page dimmer', true).dimmer('show');
        });
        socket.on('clients', function(clients) {
          var client, id, total, ua, ua_str;
          $scope.clients = clients;
          total = 0;
          for (id in clients) {
            client = clients[id];
            ua_str = client.user_agent;
            if (ua_str) {
              ua = new UAParser(ua_str);
              client.browser = ua.getBrowser();
              client.device = ua.getDevice();
              client.engine = ua.getEngine();
              client.os = ua.getOS();
              client.cpu = ua.getCPU();
            }
            ++total;
          }
          return $scope.clients_total = total;
        });
        if (config.mode === 'app') {
          host_map = {};
          ref = config.host_groups;
          for (i = 0, len = ref.length; i < len; i++) {
            host_group = ref[i];
            ref1 = host_group.hosts;
            for (j = 0, len1 = ref1.length; j < len1; j++) {
              host = ref1[j];
              host_map[host.name] = host;
            }
          }
          socket.on('info', function(message) {
            return $timeout(function() {
              var info_message, name, results;
              results = [];
              for (name in message) {
                info_message = message[name];
                results.push(host_map[name].info = process_info_message(info_message));
              }
              return results;
            });
          });
          socket.on('status', function(message) {
            return $timeout(function() {
              var name, results, status_message;
              results = [];
              for (name in message) {
                status_message = message[name];
                results.push(host_map[name].status = process_status_message(status_message));
              }
              return results;
            });
          });
          socket.on('full_status', function(message) {
            return $timeout(function() {
              var full_status_message, name, results;
              results = [];
              for (name in message) {
                full_status_message = message[name];
                results.push(host_map[name].full_status = process_full_status_message(full_status_message));
              }
              return results;
            });
          });
          socket.on('update_result', function(message) {
            return $timeout(function() {
              var name, result_message, results;
              results = [];
              for (name in message) {
                result_message = message[name];
                results.push(handle_update_result_message(host_map[name], result_message));
              }
              return results;
            });
          });
        } else {
          local_host = {
            name: 'local',
            address: 'localhost'
          };
          local_host_group = {
            name: 'Local Node',
            hosts: [local_host]
          };
          config.host_groups = [local_host_group];
          socket.on('info', function(message) {
            return $timeout(function() {
              return local_host.info = process_info_message(message);
            });
          });
          socket.on('status', function(message) {
            return $timeout(function() {
              return local_host.status = process_status_message(message);
            });
          });
          socket.on('full_status', function(message) {
            return $timeout(function() {
              return local_host.full_status = process_full_status_message(message);
            });
          });
        }
        $scope.config = config;
        $scope.socket = socket;
        handle = $interval(update_uptime, 30 * 1000);
        return $scope.$on('$destroy', function() {
          return $interval.cancel(handle);
        });
      });
    }
  ]);

  app.controller('HomeController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {}]);

  app.controller('HostController', [
    '$scope', '$http', '$timeout', '$routeParams', '$location', function($scope, $http, $timeout, $routeParams, $location) {
      var host_id, re_enable_full_status;
      host_id = $routeParams['hid'];
      re_enable_full_status = function() {
        return $scope.socket.emit('enable_full_status', host_id);
      };
      $scope.$on('$destroy', function() {
        if ($scope.socket && $scope.host) {
          $scope.socket.off('reconnect', re_enable_full_status);
          $scope.socket.emit('disable_full_status', host_id);
        }
        if ($scope.host) {
          return $scope.host.full_status = void 0;
        }
      });
      $scope.$watch('socket', function(socket) {
        var host, host_group, i, j, len, len1, ref, ref1;
        if (!socket) {
          return;
        }
        ref = $scope.config.host_groups;
        for (i = 0, len = ref.length; i < len; i++) {
          host_group = ref[i];
          ref1 = host_group.hosts;
          for (j = 0, len1 = ref1.length; j < len1; j++) {
            host = ref1[j];
            if (host.name === host_id) {
              $scope.host = host;
              $scope.host_group = host_group;
              break;
            }
          }
          if ($scope.host) {
            break;
          }
        }
        if (!$scope.host) {
          $location.path('/404').replace();
          return;
        }
        $timeout(function() {
          return $('.host-switch').dropdown();
        });
        socket.emit('enable_full_status', host_id);
        return socket.on('reconnect', re_enable_full_status);
      });
      return $scope.update = function() {
        if ($scope.host) {
          $scope.host.update_result = void 0;
          $scope.host.updating = true;
          return $scope.socket.emit('update', $scope.host.name);
        }
      };
    }
  ]);

}).call(this);

//# sourceMappingURL=app.js.map
