if [ -n "$(xmlstarlet sel -N x=http://maven.apache.org/POM/4.0.0 -t -v '/x:project/x:distributionManagement/x:repository/x:id' pom.xml)" ]; then
  echo "Resource project/x:distributionManagement/x:repository/x:id already defined in pom.xml"
  echo "Ready for release!"
else
  echo "Adding resource jdbc/templateassets to <GlobalNamingResources> in pom.xml"
  xmlstarlet ed -L -N 'x=http://maven.apache.org/POM/4.0.0' -s "/x:project" -t elem -n "distributionManagement" pom.xml
  xmlstarlet ed -L -N 'x=http://maven.apache.org/POM/4.0.0' -s "/x:project/x:distributionManagement" -t elem -n "repository" pom.xml
  xmlstarlet ed -L -N 'x=http://maven.apache.org/POM/4.0.0' -s "/x:project/x:distributionManagement/x:repository" -t elem -n "id" -v "digg-nexus" pom.xml
  xmlstarlet ed -L -N 'x=http://maven.apache.org/POM/4.0.0' -s "/x:project/x:distributionManagement/x:repository" -t elem -n "name" -v "nexus-release" pom.xml
  xmlstarlet ed -L -N 'x=http://maven.apache.org/POM/4.0.0' -s "/x:project/x:distributionManagement/x:repository" -t elem -n "url" -v "https://registry.digg.se/repository/maven-releases" pom.xml
  git add  pom.xml
  git cs -m 'choir: Prepare release'
  git push
  echo "Ready for release!"
fi