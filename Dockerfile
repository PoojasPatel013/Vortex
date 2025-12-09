FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (needed for compilation of some python packages)
RUN apt-get update && apt-get install -y \
  gcc \
  libpq-dev \
  && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir poetry && \
  poetry config virtualenvs.create false

# We need to install dependencies. 
# Since we don't have poetry.lock yet, we rely on pyproject.toml
# But for production build without lock, we might export requirements or just install via pip if we had requirements.txt
# Here we will try to install the project itself which installs dependencies.
COPY . .
RUN pip install .

# Install server dependencies explicitly if not in pyproject yet (we will add them)
RUN pip install "fastapi[all]" uvicorn sqlmodel asyncpg psycopg2-binary

EXPOSE 8000

CMD ["uvicorn", "vortex.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
