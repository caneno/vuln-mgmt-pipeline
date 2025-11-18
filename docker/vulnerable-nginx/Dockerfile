FROM nginx:1.21   
RUN echo "<h1>My Vulnerable Demo<h1>" > /usr/share/nginx/html/index.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
