
if docker inspect taildb >& /dev/null; then
    echo Container exists
    if docker inspect taildb | grep '"Status": "running"' >& /dev/null; then
        echo ...and running. Exiting.
    else
        echo ...but not running. Starting container...
        docker start taildb
        echo ...container started. Exiting.
    fi
else
    echo Container does not exist. Creating...

    docker run -tid --name taildb -p 5100:5432/tcp -v .db-data:/var/lib/postgresql/data -e POSTGRES_USER=taildb -e POSTGRES_PASSWORD=taildb postgres:17
    sqlx migrate run
    cat sample-data.sql | docker exec -i taildb psql -Utaildb
fi