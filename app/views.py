from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from .utils import extract_ips, abuse_ipdb_logic, virustotal_logic, ibm_xforce_logic, get_domain_report, extract_domains, get_user_agent_info, scan_url_virustotal
from django.shortcuts import render

def home(request):
    return render(request, 'app/index.html')

@require_http_methods(["POST"])
@csrf_protect
def check_ip(request):
    if request.method == "POST":
        ip_data = request.POST.get('ip_data', '')
        ips = extract_ips(ip_data)
        results = abuse_ipdb_logic(ips)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_ip_virustotal(request):
    if request.method == "POST":
        ip_data = request.POST.get('ip_data', '')
        ips = extract_ips(ip_data)
        results = virustotal_logic(ips)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_ip_ibm(request):
    if request.method == "POST":
        ip_data = request.POST.get('ip_data', '')
        ips = extract_ips(ip_data)
        results = ibm_xforce_logic(ips)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_domain_virustotal(request):
    if request.method == "POST":
        domains_data = request.POST.get('ip_data', '')
        domains = extract_domains(domains_data)
        results = get_domain_report(domains)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_user_agent(request):
    if request.method == "POST":
        user_agents_data_data = request.POST.get('ip_data', '')
        user_agents_raw = extract_domains(user_agents_data_data)
        results = get_user_agent_info(user_agents_raw)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_url_virustotal(request):
    if request.method == "POST":
        urls_data_data = request.POST.get('ip_data', '')
        urls_to_scan = extract_domains(urls_data_data)
        results = scan_url_virustotal(urls_to_scan)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON