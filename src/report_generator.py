"""
리포트 생성기 클래스
분석 결과를 다양한 형태로 생성하고 저장
"""

import json
import os
from datetime import datetime
from pathlib import Path
import logging

class ReportGenerator:
    """리포트 생성기 클래스"""
    
    def __init__(self, reports_dir):
        """
        리포트 생성기 초기화
        
        Args:
            reports_dir (Path): 리포트 저장 디렉토리
        """
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def save_json_report(self, report_data, output_path):
        """
        JSON 리포트 저장
        
        Args:
            report_data (dict): 리포트 데이터
            output_path (str): 저장 경로
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            
            self.logger.info(f"JSON 리포트 저장 완료: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"JSON 리포트 저장 실패: {str(e)}")
            return False
    
    def generate_summary_report(self, json_reports):
        """
        여러 분석 결과를 종합한 요약 리포트 생성
        
        Args:
            json_reports (list): JSON 리포트 경로 목록
        """
        try:
            summary_data = {
                'generated_at': datetime.now().isoformat(),
                'total_apps_analyzed': len(json_reports),
                'summary': {
                    'high_risk_apps': 0,
                    'medium_risk_apps': 0,
                    'low_risk_apps': 0,
                    'common_vulnerabilities': {},
                    'security_scores': []
                },
                'detailed_results': []
            }
            
            for report_path in json_reports:
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    # 앱 정보 추출
                    app_info = {
                        'app_name': report_data.get('app_name', 'Unknown'),
                        'package_name': report_data.get('package_name', 'Unknown'),
                        'file_name': report_data.get('file_name', 'Unknown'),
                        'security_score': report_data.get('average_cvss', 0)
                    }
                    
                    # 보안 점수별 분류
                    score = float(app_info['security_score']) if app_info['security_score'] else 0
                    if score >= 7.0:
                        summary_data['summary']['high_risk_apps'] += 1
                        app_info['risk_level'] = 'High'
                    elif score >= 4.0:
                        summary_data['summary']['medium_risk_apps'] += 1
                        app_info['risk_level'] = 'Medium'
                    else:
                        summary_data['summary']['low_risk_apps'] += 1
                        app_info['risk_level'] = 'Low'
                    
                    summary_data['summary']['security_scores'].append(score)
                    summary_data['detailed_results'].append(app_info)
                    
                    # 취약점 통계
                    if 'code_analysis' in report_data:
                        findings = report_data['code_analysis'].get('findings', {})
                        for category, vulns in findings.items():
                            if isinstance(vulns, list):
                                for vuln in vulns:
                                    vuln_type = vuln.get('type', 'Unknown')
                                    if vuln_type in summary_data['summary']['common_vulnerabilities']:
                                        summary_data['summary']['common_vulnerabilities'][vuln_type] += 1
                                    else:
                                        summary_data['summary']['common_vulnerabilities'][vuln_type] = 1
                
                except Exception as e:
                    self.logger.error(f"리포트 파싱 실패 {report_path}: {str(e)}")
                    continue
            
            # 평균 보안 점수 계산
            if summary_data['summary']['security_scores']:
                avg_score = sum(summary_data['summary']['security_scores']) / len(summary_data['summary']['security_scores'])
                summary_data['summary']['average_security_score'] = round(avg_score, 2)
            
            # 요약 리포트 저장
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_path = self.reports_dir / f"summary_report_{timestamp}.json"
            
            self.save_json_report(summary_data, summary_path)
            
            # HTML 리포트도 생성
            html_path = summary_path.with_suffix('.html')
            self.generate_html_summary(summary_data, html_path)
            
            return str(summary_path)
            
        except Exception as e:
            self.logger.error(f"요약 리포트 생성 실패: {str(e)}")
            return None
    
    def generate_html_summary(self, summary_data, output_path):
        """HTML 형태의 요약 리포트 생성"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MyMobSF_Analyzer - 분석 요약 리포트</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .summary-item {{ text-align: center; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }}
        .risk-high {{ background-color: #e74c3c; color: white; }}
        .risk-medium {{ background-color: #f39c12; color: white; }}
        .risk-low {{ background-color: #27ae60; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
        .vuln-chart {{ margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MyMobSF_Analyzer 분석 요약 리포트</h1>
        <p>생성일: {summary_data['generated_at']}</p>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <h3>총 분석된 앱</h3>
            <h2>{summary_data['total_apps_analyzed']}</h2>
        </div>
        <div class="summary-item risk-high">
            <h3>고위험 앱</h3>
            <h2>{summary_data['summary']['high_risk_apps']}</h2>
        </div>
        <div class="summary-item risk-medium">
            <h3>중위험 앱</h3>
            <h2>{summary_data['summary']['medium_risk_apps']}</h2>
        </div>
        <div class="summary-item risk-low">
            <h3>저위험 앱</h3>
            <h2>{summary_data['summary']['low_risk_apps']}</h2>
        </div>
    </div>
    
    <h2>분석 결과 상세</h2>
    <table>
        <thead>
            <tr>
                <th>앱 이름</th>
                <th>패키지명</th>
                <th>파일명</th>
                <th>보안 점수</th>
                <th>위험도</th>
            </tr>
        </thead>
        <tbody>
"""
            
            for app in summary_data['detailed_results']:
                risk_class = f"risk-{app['risk_level'].lower()}"
                html_content += f"""
            <tr>
                <td>{app['app_name']}</td>
                <td>{app['package_name']}</td>
                <td>{app['file_name']}</td>
                <td>{app['security_score']}</td>
                <td class="{risk_class}">{app['risk_level']}</td>
            </tr>
"""
            
            html_content += """
        </tbody>
    </table>
    
    <h2>주요 취약점 현황</h2>
    <table>
        <thead>
            <tr>
                <th>취약점 유형</th>
                <th>발견 횟수</th>
            </tr>
        </thead>
        <tbody>
"""
            
            for vuln_type, count in summary_data['summary']['common_vulnerabilities'].items():
                html_content += f"""
            <tr>
                <td>{vuln_type}</td>
                <td>{count}</td>
            </tr>
"""
            
            html_content += """
        </tbody>
    </table>
</body>
</html>
"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML 요약 리포트 생성 완료: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"HTML 리포트 생성 실패: {str(e)}")
            return False
