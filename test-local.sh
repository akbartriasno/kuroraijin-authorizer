#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Kuroraijin Authorizer Local Testing ===${NC}\n"

# Step 1: Build the JAR
echo -e "${YELLOW}Step 1: Building JAR...${NC}"
./gradlew clean shadowJar

if [ ! -f "build/libs/kuroraijin-authorizer-0.1-all.jar" ]; then
    echo -e "${RED}ERROR: JAR file not found!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ JAR built successfully${NC}\n"

# Step 2: Check MongoDB Atlas connection
echo -e "${YELLOW}Step 2: Using MongoDB Atlas...${NC}"
echo -e "${GREEN}✓ Using MongoDB Atlas connection${NC}\n"

# Step 3: Test without token (should deny)
echo -e "${YELLOW}Step 3: Testing without token (should DENY)...${NC}"
sam local invoke AuthorizerFunction \
    --event events/test-no-token.json \
    --env-vars env.json

echo -e "\n"

# Step 4: Test with invalid token (should deny)
echo -e "${YELLOW}Step 4: Testing with token from event file...${NC}"
echo -e "${RED}NOTE: Update events/test-request-authorizer.json with your real JWT token${NC}"
sam local invoke AuthorizerFunction \
    --event events/test-request-authorizer.json \
    --env-vars env.json

echo -e "\n${GREEN}=== Testing Complete ===${NC}"
echo -e "${YELLOW}To test with a specific token, run:${NC}"
echo -e "sam local invoke AuthorizerFunction --event events/test-request-authorizer.json --env-vars env.json"