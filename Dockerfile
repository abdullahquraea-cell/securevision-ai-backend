FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# أدوات النظام + أدوات الفحص (nmap, sqlmap)
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap sqlmap curl unzip ca-certificates dnsutils fonts-freefont-ttf \
    && rm -rf /var/lib/apt/lists/*

# تنزيل خط Amiri العربي مباشرةً (مضمون — من Google Fonts)
RUN mkdir -p /usr/share/fonts/arabic \
    && curl -fsSL https://raw.githubusercontent.com/google/fonts/main/ofl/amiri/Amiri-Regular.ttf -o /usr/share/fonts/arabic/Amiri-Regular.ttf \
    && curl -fsSL https://raw.githubusercontent.com/google/fonts/main/ofl/amiri/Amiri-Bold.ttf -o /usr/share/fonts/arabic/Amiri-Bold.ttf
# تثبيت Nuclei (أحدث إصدار)
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep '"tag_name"' | cut -d '"' -f4 | tr -d 'v') \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]