//
// Created by oueru on 2019-11-14.
//
#pragma once
#ifndef SOLIDITY_BINARYCFG_H
#define SOLIDITY_BINARYCFG_H

#endif //SOLIDITY_BINARYCFG_H

#include <libdevcore/Common.h>
#include <libevmasm/AssemblyItem.h>
#include <libsolidity/ast/AST.h>


namespace dev {
    namespace cfg {
        class Annotation {
        private:
            std::map<unsigned, u256> m_jumptarget;
            std::vector<u256> m_function_entry;
            std::map<u256,u256> m_public_function_entry;
            u256 fall_back_function_entry;
        public:
            void appendJumptarget(unsigned item_index, const u256& tag) { m_jumptarget[item_index] = tag;}
            void appendFunctiontag(const u256& tag) {m_function_entry.push_back(tag);}
            void appendPublicFunctiontag(const u256& tag1, const u256& tag2) {m_public_function_entry[tag1] = tag2;}

            void setFallBackFunctionEntry(const u256 &fallBackFunctionEntry) {
                fall_back_function_entry = fallBackFunctionEntry;
            }

            std::string printJumpTgt() const{
                std::string result = "";
                auto iter = m_jumptarget.begin();
                for(;iter != m_jumptarget.end(); iter++){
                    result += std::to_string(iter->first) + " ";
                    result += std::string(iter->second) + "\n";
                }
                return result;
            }
            std::string printFunctionEntry() const{
                std::string result = "";
                auto iter = m_function_entry.begin();
                for(;iter!=m_function_entry.end();iter++){
                    result += std::string(*iter);
                    result += "\n";
                }
                return result;
            }
            std::string printPublicFunctionEntry() const{
                std::string result = "";
                auto iter = m_public_function_entry.begin();
                for(;iter!=m_public_function_entry.end();iter++){
                    result += std::string(iter->first) + '\t' + std::string(iter->second);
                    result += "\n";
                }
                return result;
            };

            std::string printFallBack() const{
                return std::string(fall_back_function_entry) + '\n';
            }

        };

        struct OptimzedItem{
            unsigned source_start;
            unsigned source_end;
            std::vector<eth::AssemblyItem> optimzedAssemblyItems;

            OptimzedItem(unsigned int sourceStart, unsigned int sourceEnd,
                         const std::vector<eth::AssemblyItem> &optimzedAssemblyItems) : source_start(sourceStart),
                                                                                        source_end(sourceEnd),
                                                                                        optimzedAssemblyItems(
                                                                                                optimzedAssemblyItems) {}
            OptimzedItem(unsigned int sourceStart, unsigned int sourceEnd) : source_start(sourceStart), source_end(sourceEnd) {}
        };

        class OptimizedAnnotation {
        public:
            OptimizedAnnotation(unsigned int type, const std::string &functionName, const OptimzedItem &optimzedItem)
                    : type(type), function_name(functionName), optimzedItem(optimzedItem) {}

            std::string OptimizedAnnotationStr() const {
                std::string result = "";
                result += std::to_string(type) + " ";
                result += function_name + " ";
                result += std::to_string(optimzedItem.source_start) + " ";
                result += std::to_string(optimzedItem.source_end) + " \n";
                if(optimzedItem.optimzedAssemblyItems.size() > 0){
                    result += "=\n";
                    for(auto iter = optimzedItem.optimzedAssemblyItems.begin();iter != optimzedItem.optimzedAssemblyItems.end();iter++){
                        result += iter->toAssemblyText()+"\n";
                    }
                }
                return result;
            }
        private:
            unsigned type; // optimize
            std::string function_name;
            OptimzedItem optimzedItem;
        };


    }
}
