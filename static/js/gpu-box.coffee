app = angular.module 'app'

app.directive 'gpuBox', ->
  restrict: 'A'
  scope: {
    host: '='
    info: '='
    status: '='
    fullStatus: '='
    showChart: '='
  }
  templateUrl: 'static/ui/gpu_box.html'
  controller: 'GpuBoxController'
  link: (scope, element, attrs) ->
    scope.rootElement = element


app.controller 'GpuBoxController', ['$scope', '$timeout', ($scope, $timeout)->
  init_chart = ->
    max_timestamps = 50
    same_time_threshold = 1500

    $scope.data_timestamps = []
    $scope.data_gpu_utilization = []
    $scope.data_cpu_utilization = []

    ctx = $($scope.rootElement).find('.gpu-chart')
    $scope.chart = new Chart ctx,
      type: 'line'
      data:
        labels: $scope.data_timestamps
        datasets: [
          {
            label: 'GPU Utilization (%)'
            fill: false
            backgroundColor: '#21ba45'
            borderColor: '#21ba45'
            lineTension: 0
            pointRadius: 2
            data: $scope.data_gpu_utilization
          }
          {
            label: 'Total CPU Utilization (%)'
            fill: false
            backgroundColor: '#db2828'
            borderColor: '#db2828'
            lineTension: 0
            pointRadius: 2
            data: $scope.data_cpu_utilization
          }
        ]
      options:
        maintainAspectRatio: false
        scales:
          xAxes:[
            type: 'time'
            time:
              unit: 'second'
              displayFormats:
                second: 'hh:mm:ss'
          ]
          yAxes:[
            ticks:
              suggestedMin: 0
              suggestedMax: 100
          ]

    $scope.$watch 'status', (status)->
      $timeout ->
        while $scope.data_timestamps.length >= max_timestamps
          $scope.data_timestamps.shift()
        while $scope.data_gpu_utilization.length >= max_timestamps
          $scope.data_gpu_utilization.shift()

        now = new Date()
        old_timestamps = $scope.data_timestamps.length
        if old_timestamps == 0 or now - $scope.data_timestamps[old_timestamps-1] > same_time_threshold
          $scope.data_timestamps.push(new Date())

        $scope.data_gpu_utilization.push(status.utilization.gpu)
        $scope.chart.update()

    $scope.$watch 'fullStatus', (fullStatus)->
      $timeout ->
        while $scope.data_timestamps.length >= max_timestamps
          $scope.data_timestamps.shift()
        while $scope.data_cpu_utilization.length >= max_timestamps
          $scope.data_cpu_utilization.shift()

        now = new Date()
        old_timestamps = $scope.data_timestamps.length
        if old_timestamps == 0 or now - $scope.data_timestamps[old_timestamps-1] > same_time_threshold
          $scope.data_timestamps.push(new Date())

        cpu_total = 0
        for p in fullStatus.process_list
          cpu_total += p.cpu_percent
        $scope.data_cpu_utilization.push(Math.round(cpu_total))

        $scope.chart.update()


  if $scope.showChart
    $timeout(init_chart, 100)
]

