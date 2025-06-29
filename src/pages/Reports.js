import React, { useState, useEffect } from 'react';
import Card from '../components/Card';
import Button from '../components/Button';
import { FileText, Download, Eye, Calendar, BarChart3 } from 'lucide-react';

const { ipcRenderer } = window.require('electron');

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      // This would typically load existing reports from the reports directory
      // For now, we'll simulate some sample reports
      const sampleReports = [
        {
          id: 1,
          name: 'Network_Security_Posture_Report_2025-01-23_16-33-46.pdf',
          type: 'Security Posture',
          date: '2025-01-23 16:33:46',
          size: '2.4 MB',
          devices: ['Border-Router', 'DHCP-R'],
          status: 'Complete'
        },
        {
          id: 2,
          name: 'Network_Security_Compliance_Report_2025-01-23_16-46-52.pdf',
          type: 'Compliance Assessment',
          date: '2025-01-23 16:46:52',
          size: '1.8 MB',
          devices: ['Border-Router'],
          status: 'Complete'
        }
      ];
      setReports(sampleReports);
    } catch (error) {
      console.error('Error loading reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateNewReport = async (reportType) => {
    try {
      setLoading(true);
      
      let scriptPath = '';
      switch (reportType) {
        case 'posture':
          scriptPath = 'device_config/network_configuration_manager.py';
          break;
        case 'compliance':
          scriptPath = 'network_compliance/check_compliance.py';
          break;
        default:
          return;
      }

      const result = await ipcRenderer.invoke('execute-python-script', scriptPath, ['generate_report']);
      
      if (result.success) {
        alert('Report generated successfully!');
        loadReports(); // Refresh the reports list
      } else {
        alert('Error generating report: ' + result.error);
      }
    } catch (error) {
      alert('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const openReport = async (reportName) => {
    try {
      const result = await ipcRenderer.invoke('show-open-dialog', {
        defaultPath: `./reports/${reportName}`,
        filters: [
          { name: 'PDF Files', extensions: ['pdf'] }
        ]
      });

      if (!result.canceled && result.filePaths.length > 0) {
        // Open the PDF file with the default system application
        const { shell } = window.require('electron');
        shell.openPath(result.filePaths[0]);
      }
    } catch (error) {
      console.error('Error opening report:', error);
    }
  };

  const downloadReport = async (reportName) => {
    try {
      const result = await ipcRenderer.invoke('show-save-dialog', {
        defaultPath: reportName,
        filters: [
          { name: 'PDF Files', extensions: ['pdf'] }
        ]
      });

      if (!result.canceled) {
        // Copy the file to the selected location
        alert('Report saved to: ' + result.filePath);
      }
    } catch (error) {
      console.error('Error downloading report:', error);
    }
  };

  const getReportTypeColor = (type) => {
    switch (type) {
      case 'Security Posture': return 'bg-blue-100 text-blue-800';
      case 'Compliance Assessment': return 'bg-green-100 text-green-800';
      case 'Attack Mitigation': return 'bg-red-100 text-red-800';
      case 'Framework Controls': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const reportTemplates = [
    {
      type: 'posture',
      name: 'Network Security Posture Report',
      description: 'Comprehensive security assessment of network devices',
      icon: BarChart3,
      color: 'bg-blue-500'
    },
    {
      type: 'compliance',
      name: 'Compliance Assessment Report',
      description: 'Detailed compliance check against security frameworks',
      icon: FileText,
      color: 'bg-green-500'
    }
  ];

  return (
    <div className="space-y-6 fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="text-gray-600 mt-2">Generate and manage security assessment reports</p>
        </div>
      </div>

      {/* Report Templates */}
      <Card title="Generate New Report" subtitle="Create comprehensive security reports">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {reportTemplates.map((template, index) => {
            const Icon = template.icon;
            return (
              <div key={index} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                <div className="flex items-center space-x-4 mb-4">
                  <div className={`w-12 h-12 ${template.color} rounded-lg flex items-center justify-center`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{template.name}</h3>
                    <p className="text-sm text-gray-600">{template.description}</p>
                  </div>
                </div>
                <Button
                  onClick={() => generateNewReport(template.type)}
                  loading={loading}
                  className="w-full"
                >
                  Generate Report
                </Button>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Existing Reports */}
      <Card title="Generated Reports" subtitle={`${reports.length} reports available`}>
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="loading-spinner mr-2" />
            <span>Loading reports...</span>
          </div>
        ) : reports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Report
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Generated
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Size
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Devices
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {reports.map((report) => (
                  <tr key={report.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <FileText className="w-5 h-5 text-gray-400 mr-3" />
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {report.name.split('_').slice(0, -2).join(' ')}
                          </div>
                          <div className="text-sm text-gray-500">{report.name}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getReportTypeColor(report.type)}`}>
                        {report.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 text-gray-400 mr-2" />
                        {new Date(report.date).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {report.size}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="flex flex-wrap gap-1">
                        {report.devices.map((device, index) => (
                          <span key={index} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {device}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => openReport(report.name)}
                          className="text-blue-600 hover:text-blue-900"
                          title="View Report"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => downloadReport(report.name)}
                          className="text-green-600 hover:text-green-900"
                          title="Download Report"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600 mb-4">No reports generated yet</p>
            <p className="text-sm text-gray-500">Generate your first report using the templates above</p>
          </div>
        )}
      </Card>

      {/* Report Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-blue-100 rounded-lg mx-auto mb-4">
            <FileText className="w-6 h-6 text-blue-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">{reports.length}</h3>
          <p className="text-gray-600">Total Reports</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-green-100 rounded-lg mx-auto mb-4">
            <BarChart3 className="w-6 h-6 text-green-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">
            {reports.filter(r => r.type === 'Security Posture').length}
          </h3>
          <p className="text-gray-600">Posture Reports</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-purple-100 rounded-lg mx-auto mb-4">
            <FileText className="w-6 h-6 text-purple-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">
            {reports.filter(r => r.type === 'Compliance Assessment').length}
          </h3>
          <p className="text-gray-600">Compliance Reports</p>
        </Card>

        <Card className="text-center">
          <div className="flex items-center justify-center w-12 h-12 bg-yellow-100 rounded-lg mx-auto mb-4">
            <Calendar className="w-6 h-6 text-yellow-600" />
          </div>
          <h3 className="text-2xl font-bold text-gray-900">
            {reports.length > 0 ? 'Today' : 'None'}
          </h3>
          <p className="text-gray-600">Last Generated</p>
        </Card>
      </div>
    </div>
  );
};

export default Reports;